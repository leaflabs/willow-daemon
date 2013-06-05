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

/**
 * @file sockutil.h
 * @brief Socket utility library
 */

#ifndef _LIB_SOCKUTIL_H_
#define _LIB_SOCKUTIL_H_

#include <stdint.h>

/**
 * @brief Convenience for creating UDP sockets.
 *
 * Try to socket() and bind() a new UDP socket at the specified port,
 * using IPv4 or IPv6 as available.
 *
 * @param port Port to open a socket on.
 * @return On success, the socket file descriptor. On failure, an
 *         invalid socket (-1).
 */
int sockutil_get_udp_socket(uint16_t port);

/**
 * @brief Convenience for creating connected UDP sockets.
 *
 * @param host Host to connect to, presentation format (IPv4 dotted
 *             quad or IPv6 hex string).
 * @param port Port to connect to.
 * @return Socket file descriptor on success, -1 on failure.
 */
int sockutil_get_udp_connected_p(const char *host, uint16_t port);

/**
 * @brief Convenience for creating passive TCP sockets.
 *
 * @param port Port to create the socket on.
 * @param backlog Number of pending connections to allow; passed to listen().
 * @return Socket file descriptor on success, -1 on failure.
 */
int sockutil_get_tcp_passive(uint16_t port, int backlog);

/**
 * @brief Convenience for creating connected TCP sockets.
 *
 * @param host Host to connect to, presentation format (IPv4 dotted
 *             quad or IPv6 hex string).
 * @param port Port to connect to on host.
 * @return Socket file descriptor on success, -1 on failure.
 */
int sockutil_get_tcp_connected_p(const char *host, uint16_t port);

#endif
