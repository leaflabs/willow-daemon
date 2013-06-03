/* Copyright (c) 2013 LeafLabs, LLC.
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
