/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

/**
 * @file sockutil.h
 * @brief Socket utility library
 */

#ifndef _SOCKUTIL_H_
#define _SOCKUTIL_H_

#include <stdint.h>

/**
 * Try to socket() and bind() a new UDP socket at the specified port,
 * using IPv4 or IPv6 as available. On success, returns the socket
 * file descriptor. On failure, returns a invalid socket (-1).
 */
int sockutil_get_udp_socket(uint16_t port);

#endif
