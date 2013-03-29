/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

#ifndef _LIB_DAEMON_H_
#define _LIB_DAEMON_H_

#include <sys/select.h>

/**
 * @brief Become a daemon.
 * @param leave_open File descriptors to leave open. May be NULL.
 * @param flags Unused, must be zero.
 * @return 0 on success, -1 on error (in which case, errno is set
 *         appropriately.)
 */
int daemonize(fd_set *leave_open, int flags);

#endif  /* _DAEMON_H_ */
