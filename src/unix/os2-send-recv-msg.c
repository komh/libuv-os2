/* Copyright libuv project contributors. All rights reserved.                  
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

#include <InnoTekLIBC/tcpip.h>

#undef sendmsg

int uv__os2_sendmsg(int s, struct msghdr *msg, int flags) {
  struct iovec *saved_iov = msg->msg_iov;
  int len = msg->msg_iovlen * sizeof(*msg->msg_iov);
  int bytes;

  if (msg->msg_control && msg->msg_controllen)
    return uv__os2_sendfd(s, msg, flags);

  msg->msg_iov = alloca(len);
  memcpy(msg->msg_iov, saved_iov, len);

  bytes = sendmsg(s, msg, flags);

  msg->msg_iov = saved_iov;

  return bytes;
}

#undef recvmsg

/* FIXME: May receive a signature of SCM_RIGHTS. */
int uv__os2_recvmsg(int s, struct msghdr *msg, int flags) {
  struct iovec *saved_iov = msg->msg_iov;
  int len = msg->msg_iovlen * sizeof(*msg->msg_iov);
  int bytes;

  msg->msg_iov = alloca(len);
  memcpy(msg->msg_iov, saved_iov, len);

  bytes = recvmsg(s, msg, flags);

  msg->msg_iov = saved_iov;
  msg->msg_control = NULL;

  return bytes;
}

struct waitackargs {
  int fd;
  HEV hev;
};

static void waitack(void *args) {
  struct waitackargs *waa = (struct waitackargs *)args;
  ULONG rc;

  do
    rc = DosWaitEventSem(waa->hev, SEM_INDEFINITE_WAIT);
  while (rc == ERROR_INTERRUPT);

  close(waa->fd);
  DosCloseEventSem(waa->hev);

  free(waa);
}

#define MAX_MSG_FDS     64  /* up to 64 fds */

static char signature[] = {'\x7f', 'S', 'R', '\x00' };

struct messageheader {
  char sign[sizeof(signature)]; /* signature for SCM_RIGHTS */
  size_t total_len;             /* sizeof(msg_len) + sizeof(control_len) +
                                 * msg_len + control_len */
  size_t msg_len;               /* length of msg_iov */
  size_t control_len;           /* length of msg_control */
};

/* FIXME:
 * Unexpected behavior may occur if an ancilary data is sent partially.
 */
int uv__os2_sendfd(int s, struct msghdr *msg, int flags) {
  void *saved_msg_control = msg->msg_control;
  struct messageheader hdr;
  struct cmsghdr *cmsg;
  int *fds, fd;
  char *buf, *p;
  int buf_len;
  int bytes;
  size_t i;
  size_t count;
  int saved_errno;
  struct waitackargs *waas[MAX_MSG_FDS];
  struct waitackargs **waas_end = waas + MAX_MSG_FDS;
  struct waitackargs **waa = waas;
  char semname[50];
  ULONG rc;

  for (hdr.msg_len = 0, i = 0; i < msg->msg_iovlen; i++)
    hdr.msg_len += msg->msg_iov[i].iov_len;

  msg->msg_control = alloca(msg->msg_controllen);
  memcpy(msg->msg_control, saved_msg_control, msg->msg_controllen);

  memset(waas, 0, sizeof(waas));

  for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
       cmsg = CMSG_NXTHDR(msg, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
        continue;

    count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(*fds);

    for (fds = (int *)CMSG_DATA(cmsg), i = 0; i < count; i++) {
      fd = _getsockhandle(fds[i]);
      if (fd == -1)
        goto cleanup;

      *waa = calloc(sizeof(**waa), 1);
      if (!waa)
        goto cleanup;

      (*waa)->fd = dup(fds[i]);
      if ((*waa)->fd == -1)
        goto cleanup;

      snprintf(semname, sizeof(semname), "\\SEM32\\LIBUV\\sockfd\\%x", fd);
      rc = DosCreateEventSem(semname, &(*waa)->hev,
                             DCE_POSTONE | DC_SEM_SHARED, FALSE );
      if (rc)
        rc = DosOpenEventSem(semname, &(*waa)->hev);
      if (rc) {
        errno = ENOMEM;
        goto cleanup;
      }

      if (_beginthread(waitack, NULL, 256 * 1024, *waa) == -1) {
cleanup:
        saved_errno = errno;

        if (*waa) {
          DosCloseEventSem((*waa)->hev);
          close((*waa)->fd);
          free(*waa);

          *waa = NULL;
        }

        for (waa = waas; waa < waas_end && *waa; waa++)
          DosPostEventSem((*waa)->hev);

        errno = saved_errno;

        return -1;
      }

      fds[i] = fd;
      waa++;

      assert( waa != waas_end );
    }
  }

  hdr.control_len = msg->msg_controllen;
  hdr.total_len = sizeof(hdr.msg_len) +     /* msg_len */
                  sizeof(hdr.control_len) + /* msg_controllen */
                  hdr.msg_len +             /* msg_iov */
                  hdr.control_len;          /* msg_control */

  buf_len = hdr.total_len + sizeof(signature) + sizeof(hdr.total_len);
  p = buf = alloca(buf_len);

  memcpy(p, signature, sizeof(signature));
  p += sizeof(signature);

  memcpy(p, &hdr.total_len, sizeof(hdr) - sizeof(hdr.sign));
  p += sizeof(hdr) - sizeof(hdr.sign);

  for (i = 0; i < msg->msg_iovlen; i++) {
    memcpy(p, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
    p += msg->msg_iov[i].iov_len;
  }

  memcpy(p, msg->msg_control, msg->msg_controllen);

  bytes = send(s, buf, buf_len, flags);
  if (bytes != -1 && (size_t)bytes > hdr.msg_len)
    bytes = hdr.msg_len;

  msg->msg_control = saved_msg_control;

  return bytes;
}

static int impsockhandle(int os2sock) {
  PLIBCSOCKETFH pFH;
  int fd;
  int optval, optlen = sizeof(optval);
  int rc;

  if (__libsocket_getsockopt(os2sock, SOL_SOCKET, SO_TYPE, &optval, &optlen )
        == -1 ) {
    errno = ENOTSOCK;
    return -1;
  }

  rc = TCPNAMEG(AllocFHEx)(-1, os2sock, O_RDWR | F_SOCKET, 0, &fd, &pFH);
  if( rc ) {
    errno = -rc;
    return -1;
  }

  return fd;
}

int uv__os2_recvfd(int s, struct msghdr *msg, int flags) {
  struct messageheader hdr;
  int len;
  char *buf;
  int buf_len;
  char *msg_buf, *msg_buf_end;
  char *control_buf;
  char *p;
  struct cmsghdr *cmsg;
  int *fds;
  int bytes;
  size_t i;
  size_t count;
  int saved_errno;
  int impsocks[MAX_MSG_FDS];
  int *impsocks_end = impsocks + MAX_MSG_FDS;
  int *impsock = impsocks;
  char semname[50];
  HEV hevs[MAX_MSG_FDS];
  HEV *hev = hevs;

  len = recv(s, &hdr.sign, sizeof(hdr.sign), flags | MSG_PEEK );
  if (len == -1)
    return -1;

  if (len == 0) {
    msg->msg_controllen = 0;

    return 0;
  }

  if (memcmp(hdr.sign, signature, sizeof(signature)) != 0)
    return uv__os2_recvmsg(s, msg, flags);

  len = recv(s, &hdr, sizeof(hdr), flags | MSG_PEEK);
  if (len == -1)
    return -1;

  buf_len = sizeof(hdr) + hdr.msg_len + hdr.control_len;
  buf = alloca(buf_len);

  len = recv(s, buf, buf_len, flags | MSG_WAITALL);
  if (len == -1)
    return -1;

  msg_buf = buf + sizeof(hdr);
  msg_buf_end = msg_buf + hdr.msg_len;

  for (p = msg_buf, i = 0; p < msg_buf_end && i < msg->msg_iovlen; i++) {
    len = MIN(msg_buf_end - p, msg->msg_iov[i].iov_len);

    memcpy(msg->msg_iov[i].iov_base, p, len);

    p += len;
  }

  bytes = p - msg_buf;

  control_buf = msg_buf_end;

  len = MIN(hdr.control_len, msg->msg_controllen);
  memcpy(msg->msg_control, control_buf, len);
  msg->msg_controllen = len;

  memset(hevs, 0, sizeof(hevs));

  for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
       cmsg = CMSG_NXTHDR(msg, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
        continue;

    count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(*fds);

    for (fds = (int *)CMSG_DATA(cmsg), i = 0; i < count; i++) {
      *impsock = impsockhandle(fds[i]);
      if (*impsock == -1)
        goto cleanup;

      snprintf(semname, sizeof(semname), "\\SEM32\\LIBUV\\sockfd\\%x", fds[i]);
      if (DosOpenEventSem(semname, hev)) {
        errno = EINVAL;

cleanup:
        saved_errno = errno;

        close(*impsock);
        *impsock = -1;

        for (impsock = impsocks, hev = hevs;
             impsock < impsocks_end && *impsock != -1; impsock++, hev++) {
          DosCloseEventSem(*hev);
          close(*impsock);
        }

        errno = saved_errno;
        return -1;
      }

      DosPostEventSem(*hev);
      DosCloseEventSem(*hev);

      fds[i] = *impsock;

      impsock++;
      hev++;

      assert(impsock != impsocks_end);
    }
  }

  return bytes;
}
