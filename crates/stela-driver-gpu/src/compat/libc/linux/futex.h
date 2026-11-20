/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The kernel's futex operation words, which `util/futex.c`'s Linux branch
 * names; the C library's `syscall` implements them on the host's words. */
#ifndef STELA_LIBC_LINUX_FUTEX_H
#define STELA_LIBC_LINUX_FUTEX_H
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_FD 2
#define FUTEX_CLOCK_REALTIME 4
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10
#define FUTEX_BITSET_MATCH_ANY (~(unsigned int)0)
#endif
