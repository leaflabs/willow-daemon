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
 * @file src/sample.h
 *
 * libevent-aware data socket handling.
 */

#ifndef _SRC_SAMPLE_H_
#define _SRC_SAMPLE_H_

#include <stdint.h>
#include <sys/socket.h>

struct sample_session;
struct event_base;
struct ch_storage;

struct sample_session *sample_new(struct event_base *base, unsigned iface,
                                  uint16_t port, struct ch_storage *chns);
void sample_free(struct sample_session *dts);

/** Get daemon data socket's address. */
int sample_get_saddr(struct sample_session *smpl,
                     int af,
                     struct sockaddr *addr,
                     socklen_t *addrlen);
/** Get daemon data socket interface's MAC48 address. */
int sample_get_mac48(struct sample_session *smpl, uint8_t mac48[6]);

enum sample_addr {
    SAMPLE_ADDR_CLIENT,
    SAMPLE_ADDR_DNODE,
};
int sample_get_addr(struct sample_session *smpl,
                    struct sockaddr *addr,
                    socklen_t *addrlen,
                    enum sample_addr what);
int sample_set_addr(struct sample_session *smpl,
                    struct sockaddr *addr,
                    enum sample_addr what);

/**
 * Enable or disable subsample forwarding.
 *
 * If enabling, you must previously have configured client and data
 * node addresses with sample_set_addr().
 */
int sample_cfg_subsamples(struct sample_session *smpl,
                          int enable);

#endif
