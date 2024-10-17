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

#include <limits.h>
#include <dlfcn.h>
#include <libcx/spawn2.h>

static void *libcx_handle = (void *)-1L;
static int (*cx_spawn2)(int, const char *, const char * const [],
                        const char *, const char * const [],
                        const int []) = (void *)-1L;

static void *load_libcx_sym(const char *sym) {
  if (libcx_handle == (void *)-1L)
    libcx_handle = dlopen("libcx0", RTLD_LAZY);
  if (libcx_handle == NULL)
    return NULL;

  return dlsym(libcx_handle, sym);
}

#undef wait
pid_t uv__os2_wait(int *statusp) {
  static pid_t (*wait_pfn)(int *) = NULL;

  if (wait_pfn == NULL) {
    wait_pfn = load_libcx_sym("_wait");
    if (wait_pfn == NULL)
      wait_pfn = wait;
  }

  return wait_pfn(statusp);
}

#undef waitid
pid_t uv__os2_waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) {
  static int (*waitid_pfn)(idtype_t, id_t, siginfo_t *, int) = NULL;

  if (waitid_pfn == NULL) {
    waitid_pfn = load_libcx_sym("_waitid");
    if (waitid_pfn == NULL)
      waitid_pfn = waitid;
  }

  return waitid_pfn(idtype, id, infop, options);
}

#undef waitpid
pid_t uv__os2_waitpid(pid_t pid, int *statusp, int options) {
  static pid_t (*waitpid_pfn)(pid_t, int *, int) = NULL;

  if (waitpid_pfn == NULL) {
    waitpid_pfn = load_libcx_sym("_waitpid");
    if (waitpid_pfn == NULL)
      waitpid_pfn = waitpid;
  }

  return waitpid_pfn(pid, statusp, options);
}

int uv__os2_is_spawn2_mode(void) {
  if (cx_spawn2 == (void *)-1L) {
    if (getenv("LIBUV_NO_SPAWN2") == NULL)
      cx_spawn2 = load_libcx_sym("_spawn2");
    else
      cx_spawn2 = NULL;
  }

  return cx_spawn2 != NULL;
}

int uv__os2_spawn2(int mode, const char *name, const char * const argv[],
                   const char *cwd, const char * const envp[],
                   const int stdfds[]) {
  if (!uv__os2_is_spawn2_mode()) {
    errno = ENOSYS;
    return -1;
  }

  return cx_spawn2(mode, name, argv, cwd, envp, stdfds);
}
