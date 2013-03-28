/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

/**
 * @file sockutil.h
 * @brief Socket utility library
 */

#ifndef _SOCKUTIL_H_
#define _SOCKUTIL_H_

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
 * @return Socket file descriptor on success, -1 on failure.
 */
int sockutil_get_tcp_passive(uint16_t port);

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
