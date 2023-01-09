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

#define INCL_DOS
#include <os2.h>

#include "uv.h"
#include "internal.h"

uint64_t uv__hrtime(uv_clocktype_t type) {
  return gethrtime();
}


int uv_exepath(char* buffer, size_t* size) {
  char path[PATH_MAX];
  char exepath[PATH_MAX];

  if (buffer == NULL || size == NULL || *size == 0)
    return -EINVAL;

  if (_execname(path, sizeof(path)) == -1)
    return -EIO;

  /* Get a real name not an upper-cased name, and convert back-slashes to
   * slashes.
   */
  if (!realpath(path, exepath))
    return -errno;

  /* Copy to buffer at most *size bytes. */
  strncpy(buffer, exepath, *size);
  buffer[*size - 1] = '\0';
  *size = strlen(buffer);

  return 0;
}


USHORT _THUNK_FUNCTION( Dos16MemAvail )( PULONG );

uint64_t uv_get_free_memory(void) {
    ULONG ulFreeMem;

    return (( USHORT )
            ( _THUNK_PROLOG( 4 );
              _THUNK_FLAT( &ulFreeMem );
              _THUNK_CALL( Dos16MemAvail ))) == 0 ? ulFreeMem : 0;

    return 0;
}


uint64_t uv_get_total_memory(void) {
  ULONG total_mem;

  if (DosQuerySysInfo(QSV_TOTPHYSMEM, QSV_TOTPHYSMEM, &total_mem,
                      sizeof(total_mem)))
    return 0;

  return total_mem;
}


uint64_t uv_get_constrained_memory(void) {
  return 0;  /* Memory constraints are unknown. */
}


int uv_resident_set_memory(size_t* rss) {
  /* FIXME: right ? */

  ULONG resident_mem;

  if (DosQuerySysInfo(QSV_TOTRESMEM, QSV_TOTRESMEM, &resident_mem,
                      sizeof(resident_mem)))
    return -EINVAL;

  *rss = resident_mem;

  return 0;
}


int uv_uptime(double* uptime) {
  ULONG ms;

  if (DosQuerySysInfo(QSV_MS_COUNT, QSV_MS_COUNT, &ms, sizeof(ms)))
    return -EINVAL;

  *uptime = ms / 1000;

  return 0;
}


void uv_loadavg(double avg[3]) {
  /* TODO: FIXME */
  avg[0] = avg[1] = avg[2] = 0;
}


int uv_cpu_info(uv_cpu_info_t** cpu_infos, int* count) {
  /* TODO: FIXME */

  return -ENOSYS;
}


int uv_interface_addresses(uv_interface_address_t** addresses, int* count) {
  /* TODO: FIXME */

  return -ENOSYS;
}


void uv_free_interface_addresses(uv_interface_address_t* addresses,
  int count) {
  /* TODO: FIXME */
}
