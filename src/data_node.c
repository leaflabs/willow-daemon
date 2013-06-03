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

#include "data_node.h"

#include <time.h>

#include "logging.h"
#include "raw_packets.h"

static int _dnode_do_req_res(struct dnode_session *dnsession,
                             uint8_t req_p_flags);

int dnode_start_acquire(struct dnode_session *dnsession,
                        uint32_t start_bsmp_idx)
{

    /* Write STOP to top level state register */
    if (-1 == dnode_write_reg(dnsession, RAW_RTYPE_TOP, RAW_RADDR_TOP_STATE,
                              RAW_TOP_STOP)) {
        log_ERR("can't stop top module");
        return -1;
    }

    /* Write STOP to UDP module state register */
    if (-1 == dnode_write_reg(dnsession, RAW_RTYPE_UDP, RAW_RADDR_UDP_STATE,
                              RAW_UDP_STOP)) {
        log_ERR("can't stop UDP module");
        return -1;
    }

    /* Read DAQ chip ready register and confirm that the desired chips
     * are "alive" */
    uint32_t chips_alive;
    if (-1 == dnode_read_reg(dnsession, RAW_RTYPE_DAQ,
                             RAW_RADDR_DAQ_CHIP_ALIVE, &chips_alive)) {
        log_ERR("can't read DAQ chip status");
        return -1;
    }
    if (chips_alive != 0xFFFFFFFF) {
        log_ERR("some chips are dead: DAQ_CHIP_ALIVE=0x%x", chips_alive);
        return -1;              /* TODO continue? */
    }

    /* Write READY_WRITE to SATA module state register */
    if (-1 == dnode_write_reg(dnsession, RAW_RTYPE_SATA,
                              RAW_RADDR_SATA_STATE, RAW_SATA_READY_WRITE)) {
        log_ERR("can't ready the SATA module");
        return -1;
    }

    /* Configure top and bottom words of experiment cookie */
    assert(sizeof(time_t) == 8 && "we need 64-bit time_t");
    time_t cookie = time(NULL);
    uint32_t cookie_h = (uint32_t)(cookie >> 32);
    uint32_t cookie_l = (uint32_t)(cookie & 0xFFFFFFFF);
    if (-1 == dnode_write_reg(dnsession, RAW_RTYPE_TOP,
                              RAW_RADDR_TOP_EXP_CK_H, cookie_h) ||
        -1 == dnode_write_reg(dnsession, RAW_RTYPE_TOP,
                              RAW_RADDR_TOP_EXP_CK_L, cookie_l)) {
        log_ERR("can't set experiment cookie");
        return -1;
    }

    /* Write desired starting board sample index to DAQ board
     * sample index register */
    if (-1 == dnode_write_reg(dnsession, RAW_RTYPE_DAQ,
                              RAW_RADDR_DAQ_BSMP_START, start_bsmp_idx)) {
        log_ERR("can't set starting board sample index");
        return -1;
    }

    /* Write BEGIN_ACQ to top level state register */
    if (-1 == dnode_write_reg(dnsession, RAW_RTYPE_TOP,
                              RAW_RADDR_TOP_STATE, RAW_TOP_BEGIN_ACQ)) {
        log_ERR("can't start acquisition in top-level module");
        return -1;
    }

    /* Success! */
    return 0;
}

int dnode_stop_acquire(struct dnode_session *dnsession,
                       uint32_t *stop_bsmp_idx)
{
    /* Write STOP state to top level state register */
    if (-1 == dnode_write_reg(dnsession, RAW_RTYPE_TOP,
                              RAW_RADDR_TOP_STATE, RAW_TOP_STOP)) {
        log_ERR("can't stop top level module");
        return -1;
    }
    /* Read last index number from SATA write register */
    uint32_t stop_idx;
    if (-1 == dnode_read_reg(dnsession, RAW_RTYPE_SATA,
                             RAW_RADDR_SATA_W_IDX, &stop_idx)) {
        log_ERR("can't read last board sample index from SATA module");
        return -1;
    }
    /* Success! */
    *stop_bsmp_idx = stop_idx;
    return 0;
}

int dnode_write_reg(struct dnode_session *dnsession,
                    uint8_t r_type, uint8_t r_addr, uint32_t r_val)
{
    struct raw_cmd_req *rcmd = raw_req(dnsession->req);
    rcmd->r_type = r_type;
    rcmd->r_addr = r_addr;
    rcmd->r_val = r_val;
    if (_dnode_do_req_res(dnsession, RAW_PFLAG_RIOD_W) == -1) {
        return -1;
    }
    if (raw_r_val(dnsession->res) != r_val) {
        log_ERR("response r_val %u doesn't match request's %u",
                raw_r_val(dnsession->res), r_val);
        return -1;
    }
    return 0;
}

int dnode_read_reg(struct dnode_session *dnsession,
                   uint8_t r_type, uint8_t r_addr, uint32_t *r_val)
{
    struct raw_cmd_req *rcmd = raw_req(dnsession->req);
    rcmd->r_type = r_type;
    rcmd->r_addr = r_addr;
    rcmd->r_val = 0;
    if (_dnode_do_req_res(dnsession, RAW_PFLAG_RIOD_R) == -1) {
        return -1;
    }
    *r_val = raw_r_val(dnsession->res);
    return 0;
}

static int _dnode_do_req_res(struct dnode_session *dnsession,
                             uint8_t req_p_flags)
{
    int ret = -1;

    int sockfd = dnsession->cc_sock;
    struct raw_pkt_cmd *req = dnsession->req;
    struct raw_pkt_cmd *res = dnsession->res;

    /* Restore consistent packet header state */
    raw_packet_init(req, RAW_MTYPE_REQ, req_p_flags);
    raw_packet_init(res, RAW_MTYPE_RES, 0);
    /* Sending mangles r_id, so cache it. */
    uint16_t req_id = raw_r_id(req);

    if (raw_cmd_send(sockfd, req, 0) == -1) {
        log_ERR("request %u: can't send request: %m", req_id);
        goto out;
    }
    int recv_status = raw_cmd_recv(sockfd, res, 0);
    if (recv_status == 0) {
        /* Remote closed the connection. Make sure we don't try to
         * contact it again, and bail.*/
        dnsession->cc_sock = -1;
        goto out;
    }
    if (recv_status == -1) {
        log_ERR("request %u: can't get response: %m", req_id);
        goto out;
    }
    uint16_t res_id = raw_r_id(res);
    if (res_id != req_id) {
        log_ERR("request %u: unexpected response r_id=%u", req_id, res_id);
        goto out;
    }
    if (raw_pkt_is_err(res)) {
        log_ERR("request %u: received error response, mtype %u, flags 0x%x",
                req_id, raw_mtype(res), raw_pflags(res));
        goto out;
    }
    ret = 0;
 out:
    raw_req(req)->r_id = req_id + 1;
    return ret;
}
