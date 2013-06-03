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
 * Data node control interface.
 *
 * IMPORTANT:
 *
 * Any one of the network I/O routines which operate on the command
 * socket may set the argument dnode_session->cc_sock value to -1 if
 * the connection is closed by the remote data node. They will always
 * return an error status when this happens, but you must check the
 * cc_sock field and re-connect if necessary.
 *
 * TODO:
 * - network configuration routines
 */

#ifndef _SRC_DATA_NODE_H_
#define _SRC_DATA_NODE_H_

#include <stdint.h>

struct raw_pkt_cmd;
struct ch_storage;
struct timespec;

/** Encapsulates state needed for dealing with a connected data node */
struct dnode_session {
    int cc_sock;
    int dt_sock;
    struct raw_pkt_cmd *req;
    struct raw_pkt_cmd *res;
    struct ch_storage *chns;
    const struct timespec *pkt_recv_timeout;
};

/**
 * Start acquisition.
 *
 * Stop the datanode, then reconfigure it for acquisition, with
 * starting board sample index start_bsmp_idx (this is normally zero).
 *
 * @param dnsession Data node session
 * @param start_bsmp_idx Desired index of first board sample
 * @return 0 on success, -1 on failure
 */
int dnode_start_acquire(struct dnode_session *dnsession,
                        uint32_t start_bsmp_idx);

/**
 * Stop acquisition.
 *
 * Stop the datanode, which should be acquiring data. On success,
 * stop_bsmp_idx will hold the index of the last valid board sample.
 *
 * @param dnsession Data node session
 * @param stop_bsmp_idx Value-result argument, last valid board sample
 * @return 0 on success, -1 on failure
 */
int dnode_stop_acquire(struct dnode_session *dnsession,
                       uint32_t *stop_bsmp_idx);

/**
 * Write a value to a register.
 *
 * Write the value r_val to the register at r_addr in module r_type.
 *
 * @param r_type module whose register to write (RAW_RTYPE_*).
 * @param r_addr address of register to write (RAW_RADDR_*).
 * @param r_val value to write to r_addr.
 * @return 0 on success, -1 on failure
 */
int dnode_write_reg(struct dnode_session *dnsession,
                    uint8_t r_type, uint8_t r_addr, uint32_t r_val);

/**
 * Read a value from a register
 *
 * Store the value in register r_addr from module r_type into *r_val.
 *
 * @param r_type module whose register to read (RAW_RTYPE_*).
 * @param r_addr address of register to read (RAW_RADDR_*).
 * @param r_val on success, holds the value read from register.
 * @return 0 on success, -1 on failure
 */
int dnode_read_reg(struct dnode_session *dnsession,
                   uint8_t r_type, uint8_t r_addr, uint32_t *r_val);

#endif
