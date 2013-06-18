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
 * @file src/control.h
 *
 * libevent-aware abstract class for client/data node control
 * connections. Basic usage (error handling omitted):
 *
 *    struct control_session *cs = control_new(base,
 *                                             client_port,
 *                                             dnode_addr,
 *                                             dnode_c_port,
 *                                             sample_port);
 *    event_base_dispatch(base);
 *    control_free(cs);
 */

#ifndef _SRC_CONTROL_H_
#define _SRC_CONTROL_H_

#include <stdint.h>

struct control_session;
struct event_base;

/**
 * Start a new control session
 *
 * When finished, free it with control_free().
 *
 * @param base Event base to install callbacks into
 * @param client_port Port to listen on for client connections
 * @param dnode_addr Address to connect to for data node control socket
 * @param dnode_c_port Port to connect to for data node control socket
 * @param sample_port UDP port to receive data node sample data on
 * @see control_free()
 */
struct control_session* control_new(struct event_base *base,
                                    uint16_t client_port,
                                    const char* dnode_addr,
                                    uint16_t dnode_c_port,
                                    uint16_t sample_port);

/**
 * Free resources acquired by a control session.
 * @param cs Control session
 */
void control_free(struct control_session *cs);

/**
 * Get a control session's base.
 * @param cs Control session
 * @return Current event_base if started, NULL otherwise.
 */
struct event_base* control_get_base(struct control_session *cs);

#endif
