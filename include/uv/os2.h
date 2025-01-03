/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
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

#ifndef UV_OS2_H
#define UV_OS2_H

/* Include all the OS/2 headers */
#define OS2EMX_PLAIN_CHAR
#define INCL_BASE
#define INCL_PM
#include <os2.h>

/* OS/2 lacks getaddrinfo(), freeaddrinfo(), getnameinfo() and socklen_t */

#include <os2compat/sys/socket.h>
#include <os2compat/netdb.h>

/* OS/2 lacks IPv6 support. However, below declarations make a compiler
 * happy.
 */

#define IPV6_JOIN_GROUP     20
#define IPV6_LEAVE_GROUP    21

#define IPV6_ADD_MEMBERSHIP     IPV6_JOIN_GROUP
#define IPV6_DROP_MEMBERSHIP    IPV6_LEAVE_GROUP

#define IPV6_UNICAST_HOPS       16
#define IPV6_MULTICAST_IF       17
#define IPV6_MULTICAST_HOPS     18
#define IPV6_MULTICAST_LOOP     19

#define IPPROTO_IPV6    41

#define INET6_ADDRSTRLEN    46

#include <stdint.h> /* integer types */
#include <sys/un.h> /* sa_family_t */

#ifndef _SS_MAXSIZE
/* struct sockaddr_storage from
 * http://pubs.opengroup.org/onlinepubs/009696699/basedefs/sys/socket.h.html.
 */

/* Desired design of maximum size and alignment. */
#define _SS_MAXSIZE 128 /* Implementation-defined maximum size. */
#define _SS_ALIGNSIZE (sizeof(int64_t))
        /* Implementation-defined desired alignment. */

/* Definitions used for sockaddr_storage structure paddings design. */
#define _SS_PAD1SIZE (_SS_ALIGNSIZE - (sizeof(uint8_t) + sizeof(sa_family_t)))
#define _SS_PAD2SIZE (_SS_MAXSIZE - (sizeof(uint8_t) + sizeof(sa_family_t)+ \
                      _SS_PAD1SIZE + _SS_ALIGNSIZE))
struct sockaddr_storage {
    uint8_t      ss_len;     /* Length of structure. */
    sa_family_t  ss_family;  /* Address family. */
/* Following fields are implementation-defined. */
    char _ss_pad1[_SS_PAD1SIZE];
        /* 6-byte pad; this is to make implementation-defined
         * pad up to alignment field that follows explicit in
         * the data structure.
         */
    int64_t _ss_align;  /* Field to force desired structure
                         * storage alignment.
                         */
    char _ss_pad2[_SS_PAD2SIZE];
        /* 112-byte pad to achieve desired size,
         * _SS_MAXSIZE value minus size of ss_len, ss_family
         * __ss_pad1, __ss_align fields is 112.
         */
};
#endif

struct in6_addr
{
    uint8_t s6_addr[16];
};

struct sockaddr_in6
{
    uint8_t         sin6_len;
    uint8_t         sin6_family;
    uint16_t        sin6_port;
    uint32_t        sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t        sin6_scope_id;
};

struct ipv6_mreq
{
    /* IPv6 multicast address of group */
    struct in6_addr ipv6mr_multiaddr;

    /* local interface */
    unsigned int ipv6mr_interface;
};

static const struct in6_addr in6addr_any =
    { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } };

/* OS/2 lacks scandir() and alphasort() */

#include <os2compat/dirent.h>

/* OS/2 select() does not support handles of pipe() */

#include <io.h>

__attribute__((unused))
static int uv__os2_pipe(int *fds) {
  int r;

  r = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

  shutdown(fds[0], SHUT_WR);
  shutdown(fds[1], SHUT_RD);

  return r;
}
#define pipe(fds) uv__os2_pipe(fds)

/* OS/2 kLIBC defines IOV_MAX to 1024, but it accepts up to 16 actaully */

#include <sys/syslimits.h>

#undef IOV_MAX
#define IOV_MAX 16

/* OS/2 sendmsg()/recvmsg() alter iov_base and iov_len, and do not support
 * SCM_RIGHTS
 */

int uv__os2_sendmsg(int s, struct msghdr *msg, int flags);
#define sendmsg(s, m, f) uv__os2_sendmsg((s), (m), (f))

int uv__os2_recvmsg(int s, struct msghdr *msg, int flags);
#define recvmsg(s, m, f) uv__os2_recvmsg((s), (m), (f))

int uv__os2_sendfd(int s, struct msghdr *msg, int flags);
int uv__os2_recvfd(int s, struct msghdr *msg, int flags);

/* LIBCx provides spawn2() which is an improved function of spawn*(),
 * and wait*() functions for it
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <libcx/spawn2.h>

pid_t uv__os2_wait(int *statusp);
#define wait(s) uv__os2_wait(s)

pid_t uv__os2_waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
#define waitid(t, id, info, o) uv__os2_waitid(t, id, inf, o)

pid_t uv__os2_waitpid(pid_t pid, int *statusp, int options);
#define waitpid(p, s, o) uv__os2_waitpid(p, s, o)

int uv__os2_is_spawn2_mode(void);
int uv__os2_spawn2(int mode, const char *name, const char * const argv[],
                   const char *cwd, const char * const envp[],
                   const int stdfds[]);

/* Platform-specific definitions for UV_FS_EVENT support. */
#define UV_PLATFORM_FS_EVENT_FIELDS                                           \
  int tid;                                                                    \
  HEV refresh;                                                                \
  int quit;                                                                   \
  uv__io_t fs_watcher;                                                        \
  int sync_fds[2];                                                            \
  const char *name;                                                           \
  int event;                                                                  \
  int status;

#endif /* UV_OS2_H */
