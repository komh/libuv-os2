/* Copyright libuv project contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "uv.h"
#include "internal.h"

#include <errno.h>
#include <sys/dirtree.h>

#define DEFAULT_REFRESH_TIME    1500    /* ms */

#define WRITE_CALL(h)                                                         \
  do {                                                                        \
    int n;                                                                    \
    n = write((h)->sync_fds[1], "c", 1);                                      \
    assert(n == 1);                                                           \
  } while(0)

#define READ_CALL(h)                                                          \
  do {                                                                        \
    char buf;                                                                 \
    int n;                                                                    \
    n = read((h)->sync_fds[0], &buf, 1);                                      \
    assert(n == 1 && buf == 'c');                                             \
  } while( 0 )

#define WRITE_ACK(h)                                                          \
  do {                                                                        \
    int n;                                                                    \
    n = write((h)->sync_fds[0], "a", 1);                                      \
    /* uv_fs_event_stop() in a call back may close sync_fds */                \
    assert(n == 1 || (n == -1 && errno == EBADF));                            \
  } while(0)

#define READ_ACK(h)                                                           \
  do {                                                                        \
    char buf;                                                                 \
    int n;                                                                    \
    n = read((h)->sync_fds[1], &buf, 1);                                      \
    assert(n == 1 && buf == 'a');                                             \
  } while( 0 )

#define CALL_CB(h, n, e, s)                                                   \
  do {                                                                        \
    (h)->name = (n);                                                          \
    (h)->event = (e);                                                         \
    (h)->status = (s);                                                        \
    WRITE_CALL((h));                                                          \
    READ_ACK((h));                                                            \
  } while( 0 )

static void uv__fs_watch_thread(void *arg) {
  uv_fs_event_t* handle = arg;
  int refreshtime;
  struct stat st;
  const char *dir;
  const char* mask;
  char dname[_MAX_PATH];
  char fname[_MAX_PATH];
  struct _dt_tree* dtold = NULL;
  struct _dt_tree* dtnew = NULL;
  struct _dt_node* nodeold;
  struct _dt_node* nodenew;
  APIRET rc;

  if (_getenv_int("LIBUV_FS_EVENT_REFRESH_TIME", &refreshtime) == -1)
    refreshtime = DEFAULT_REFRESH_TIME;

  stat(handle->path, &st);
  if (S_ISDIR(st.st_mode)) {
    dir = handle->path;
    mask = "*.*";
  } else {
    _dt_split(handle->path, dname, fname);
    dir = dname;
    mask = fname;
  }

  dtnew = _dt_read(dir, mask, _DT_NOCPDIR/* exclude '.' and '..' */);
  _dt_sort(dtnew,
           "fn" /* directory first, ascending ASCII order file names */);

  DosSetPriority(PRTYS_THREAD, PRTYC_IDLETIME, 0, 0);

  for(;;) {
    do
      rc = DosWaitEventSem(handle->refresh, refreshtime);
    while (rc == ERROR_INTERRUPT);
    DosResetEventSem(handle->refresh, &rc);

    if (handle->quit)
      break;

    free(dtold);
    dtold = dtnew;

    dtnew = _dt_read(dir, mask, _DT_NOCPDIR/* exclude '.' and '..' */);
    _dt_sort(dtnew,
             "fn" /* directory first, ascending ASCII order file names */);

    nodeold = dtold->tree;
    nodenew = dtnew->tree;
    while (!handle->quit && nodeold != NULL && nodenew != NULL) {
      int diff = strcmp(nodeold->name, nodenew->name);

      if (diff < 0) {
        CALL_CB(handle, nodeold->name, UV_RENAME, 0);
        nodeold = nodeold->next;
      } else if (diff > 0) {
        CALL_CB(handle, nodenew->name, UV_RENAME, 0);
        nodenew = nodenew->next;
      } else {
        if (nodeold->size != nodenew->size ||
            nodeold->mtime != nodenew->mtime ||
            nodeold->attr != nodenew->attr)
          CALL_CB(handle, nodeold->name, UV_CHANGE, 0);

        nodeold = nodeold->next;
        nodenew = nodenew->next;
      }
    }

    while (!handle->quit && nodeold != NULL) {
      CALL_CB(handle, nodeold->name, UV_RENAME, 0);
      nodeold = nodeold->next;
    }

    while (!handle->quit && nodenew != NULL) {
      CALL_CB(handle, nodenew->name, UV_RENAME, 0);
      nodenew = nodenew->next;
    }
  }

  free(dtold);
  free(dtnew);
}

int uv_fs_event_init(uv_loop_t* loop, uv_fs_event_t* handle) {
  uv__handle_init(loop, (uv_handle_t*) handle, UV_FS_EVENT);

  return 0;
}

static void uv__fs_watch_cb(uv_loop_t* l, uv__io_t* w, unsigned int e) {
  uv_fs_event_t* handle;

  handle = container_of(w, uv_fs_event_t, fs_watcher);
  READ_CALL(handle);
  handle->cb(handle, handle->name, handle->event, handle->status);
  WRITE_ACK(handle);
}

int uv_fs_event_start(uv_fs_event_t* handle, uv_fs_event_cb cb,
                      const char* filename, unsigned int flags) {
  struct stat st;
  int err;

  if (uv__is_active(handle))
    return UV_EINVAL;

  if (stat(filename, &st) == -1)
    return UV__ERR(errno);

  handle->cb = cb;
  handle->path = uv__strdup(filename);
  if (handle->path == NULL)
    return UV_ENOMEM;

  handle->refresh = NULLHANDLE;
  if (DosCreateEventSem(NULL, &handle->refresh, 0, FALSE) != 0) {
    err = UV_ENOMEM;
    goto error;
  }

  handle->sync_fds[0] = -1;
  handle->sync_fds[1] = -1;
  err = uv_socketpair(SOCK_STREAM, 0, handle->sync_fds, 0, 0);
  if (err != 0)
    goto error;

  uv__handle_start(handle);
  uv__io_init(&handle->fs_watcher, uv__fs_watch_cb, handle->sync_fds[0]);
  uv__io_start(handle->loop, &handle->fs_watcher, POLLIN);

  handle->quit = 0;

  handle->tid = _beginthread(uv__fs_watch_thread, NULL, 1024 * 1024, handle);
  if (handle->tid == -1) {
    err = UV__ERR(errno);
    goto error;
  }

  return 0;

error:
  uv__io_close(handle->loop, &handle->fs_watcher);

  if (uv__is_active(handle))
    uv__handle_stop(handle);

  if (handle->sync_fds[0] != -1)
    uv__close(handle->sync_fds[0]);

  if (handle->sync_fds[1] != -1)
    uv__close(handle->sync_fds[1]);

  if (handle->refresh != NULLHANDLE) {
    DosCloseEventSem(handle->refresh);
    handle->refresh = NULLHANDLE;
  }

  if (handle->path) {
    uv__free(handle->path);
    handle->path = NULL;
  }

  return err;
}

int uv_fs_event_stop(uv_fs_event_t* handle) {
  TID tid;
  APIRET rc;

  if (!uv__is_active(handle))
    return 0;

  handle->quit = 1;
  DosPostEventSem(handle->refresh);
  WRITE_ACK(handle);

  tid = handle->tid;
  do
    rc = DosWaitThread(&tid, DCWW_WAIT);
  while (rc == ERROR_INTERRUPT);

  uv__io_close(handle->loop, &handle->fs_watcher);
  uv__handle_stop(handle);

  uv__close(handle->sync_fds[0]);
  uv__close(handle->sync_fds[1]);
  handle->sync_fds[0] = -1;
  handle->sync_fds[1] = -1;

  DosCloseEventSem(handle->refresh);
  handle->refresh = NULLHANDLE;

  uv__free(handle->path);
  handle->path = NULL;

  return 0;
}

void uv__fs_event_close(uv_fs_event_t* handle) {
  uv_fs_event_stop(handle);
}
