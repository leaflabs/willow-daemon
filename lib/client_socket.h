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
 * @file lib/client_socket.h
 *
 * Definitions for transmitting length prefixes for protocol buffers
 * on client sockets.
 */

#ifndef _LIB_CLIENT_SOCKET_H_
#define _LIB_CLIENT_SOCKET_H_

#include <arpa/inet.h>

/* Client message length prefix type. Signed so -1 can mean "still
 * waiting to read length" */
typedef int32_t client_cmd_len_t;
#define CLIENT_CMDLEN_SIZE sizeof(client_cmd_len_t)
#define CLIENT_CMDLEN_WAITING (-1)

/* Google says individual protocol buffers should be < 1 MB each:
 *
 * https://developers.google.com/protocol-buffers/docs/techniques#large-data
 *
 * So we might as well try to enforce reasonably good behavior. It's a
 * protocol error to send messages that are too long, and we are free
 * to close connections for misbehavior. */
#define CLIENT_CMD_MAX_SIZE (2 * 1024 * 1024)

/* Convert a client message length from network to host byte ordering */
static inline client_cmd_len_t client_cmd_ntoh(client_cmd_len_t net)
{
    return ntohl(net);
}

/* Convert client message length from host to network byte ordering */
static inline client_cmd_len_t client_cmd_hton(client_cmd_len_t host)
{
    return htonl(host);
}


#endif
