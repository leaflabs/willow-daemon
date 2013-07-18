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
 * @file libsng/sng.h
 *
 * Header for interacting with SNG daemon.
 */

#ifndef _LIBSNG_SNG_H_
#define _LIBSNG_SNG_H_

#include <sys/socket.h>
#include <sys/types.h>
#include "proto/control.pb-c.h"

/**
 * Open a connection to the daemon.
 *
 * At most one connection can be open at once.
 *
 * @param host Daemon hostname or IP address
 * @param port Port to connect to on host
 * @return 0 on success, -1 on error.
 */
int sng_open_connection(const char *host, uint16_t port);

/**
 * Close an open connection to the daemon.
 *
 * @return 0 on success, -1 on failure.
 */
int sng_close_connection(void);

/**
 * Store some samples to disk.
 *
 * A connection to the daemon must be open.
 *
 * @param store Protocol message which configures sample storage.
 * @param response Response received from daemon. Note that this response
 *                 may indicate an error.
 * @return 0 when a response is received, -1 if no response or incorrect
 *         response is received.
 */
int sng_store_samples(ControlCmdStore *store, ControlResponse *response);

#endif
