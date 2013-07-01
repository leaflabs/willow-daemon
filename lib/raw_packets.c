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

#include "raw_packets.h"

#include <errno.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "logging.h"

/*********************************************************************
 * Initialization and convenience
 */

void raw_packet_init(void *packet, uint8_t mtype, uint8_t flags)
{
    struct raw_pkt_header *ph = packet;
    ph->_p_magic = RAW_PKT_HEADER_MAGIC;
    ph->p_proto_vers = RAW_PKT_HEADER_PROTO_VERS;
    ph->p_mtype = mtype;
    ph->p_flags = flags;

    if (mtype == RAW_MTYPE_ERR) {
        struct raw_pkt_cmd *pkt = packet;
        memset(&pkt->p, 0, sizeof(struct raw_cmd_err));
    }
}

void raw_req_init(struct raw_pkt_cmd *req, uint8_t flags, uint16_t r_id,
                  uint8_t r_type, uint8_t r_addr, uint32_t r_val)
{
    raw_packet_init(req, RAW_MTYPE_REQ, flags);
    struct raw_cmd_req *rcmd = raw_req(req);
    rcmd->r_id = r_id;
    rcmd->r_type = r_type;
    rcmd->r_addr = r_addr;
    rcmd->r_val = r_val;
}

void raw_res_init(struct raw_pkt_cmd *res, uint8_t flags, uint16_t r_id,
                  uint8_t r_type, uint8_t r_addr, uint32_t r_val)
{
    raw_packet_init(res, RAW_MTYPE_RES, flags);
    struct raw_cmd_res *rcmd = raw_res(res);
    rcmd->r_id = r_id;
    rcmd->r_type = r_type;
    rcmd->r_addr = r_addr;
    rcmd->r_val = r_val;
}

void raw_pkt_copy(void *dst, const void *src)
{
    memcpy(dst, src, raw_pkt_size(src));
}

int raw_num_regs(uint8_t r_type)
{
    switch (r_type) {
    case RAW_RTYPE_ERR:
        return RAW_RADDR_ERR_NREGS;
    case RAW_RTYPE_CENTRAL:
        return RAW_RADDR_CENTRAL_NREGS;
    case RAW_RTYPE_SATA:
        return RAW_RADDR_SATA_NREGS;
    case RAW_RTYPE_DAQ:
        return RAW_RADDR_DAQ_NREGS;
    case RAW_RTYPE_UDP:
        return RAW_RADDR_UDP_NREGS;
    case RAW_RTYPE_GPIO:
        return RAW_RADDR_GPIO_NREGS;
    default:
        return -1;
    }
}

size_t raw_pkt_size(const void *pkt)
{
    uint8_t mtype = raw_mtype(pkt);
    switch (mtype) {
    case RAW_MTYPE_REQ: /* fall through */
    case RAW_MTYPE_RES: /* fall through */
    case RAW_MTYPE_ERR:
        return sizeof(struct raw_pkt_cmd);
    case RAW_MTYPE_BSUB:
        return sizeof(struct raw_pkt_bsub);
    case RAW_MTYPE_BSMP:
        return raw_bsmp_size(pkt);
    }
    assert(0 && "invalid packet type");
    return 0;
}

/*********************************************************************
 * Network I/O
 */

#define raw_ph_hton(ph) ((void)0)
#define raw_ph_ntoh(ph) ((void)0)
#define raw_samp_hton(samp_val) htons(samp_val)
#define raw_samp_ntoh(samp_val) ntohs(samp_val)
#define raw_err_hton(pkt) ((void)0)
#define raw_err_ntoh(pkt) ((void)0)
#define raw_mtype_hton(mtype) (mtype)
#define raw_mtype_ntoh(mtype) (mtype)

static void raw_req_hton(struct raw_pkt_cmd *req)
{
    struct raw_cmd_req *rcmd = raw_req(req);
    raw_ph_hton(&req->ph);
    rcmd->r_id = htons(raw_r_id(req));
    rcmd->r_val = htonl(raw_r_val(req));
}

static void raw_res_hton(struct raw_pkt_cmd *res)
{
    struct raw_cmd_res *rcmd = raw_res(res);
    raw_ph_hton(&res->ph);
    rcmd->r_id = htons(raw_r_id(res));
    rcmd->r_val = htonl(raw_r_val(res));
}

static void raw_bsub_hton(struct raw_pkt_bsub *bsub)
{
    bsub->b_cookie_h = htonl(bsub->b_cookie_h);
    bsub->b_cookie_l = htonl(bsub->b_cookie_l);
    bsub->b_id = htonl(bsub->b_id);
    bsub->b_sidx = htonl(bsub->b_sidx);
    bsub->b_chip_live = htonl(bsub->b_chip_live);
    for (size_t i = 0; i < RAW_BSUB_NSAMP; i++) {
        bsub->b_samps[i] = raw_samp_hton(bsub->b_samps[i]);
    }
    bsub->b_gpio = htons(bsub->b_gpio);
}

static void raw_bsmp_hton(struct raw_pkt_bsmp *bsmp)
{
    bsmp->b_cookie_h = htonl(bsmp->b_cookie_h);
    bsmp->b_cookie_l = htonl(bsmp->b_cookie_l);
    bsmp->b_id = htonl(bsmp->b_id);
    bsmp->b_sidx = htonl(bsmp->b_sidx);
    bsmp->b_chip_live = htonl(bsmp->b_chip_live);
    for (size_t i = 0; i < RAW_BSMP_NSAMP; i++) {
        bsmp->b_samps[i] = raw_samp_hton(bsmp->b_samps[i]);
    }
}

int raw_pkt_hton(void *pkt)
{
    struct raw_pkt_header *ph = pkt;
    if ((ph->_p_magic != RAW_PKT_HEADER_MAGIC ||
         ph->p_proto_vers > RAW_PKT_HEADER_PROTO_VERS)) {
        return -1;
    }
    raw_ph_hton(pkt);
    switch (raw_mtype(pkt)) {
    case RAW_MTYPE_REQ:
        raw_req_hton((struct raw_pkt_cmd*)pkt);
        return 0;
    case RAW_MTYPE_RES:
        raw_res_hton((struct raw_pkt_cmd*)pkt);
        return 0;
    case RAW_MTYPE_ERR:
        raw_err_hton((struct raw_pkt_cmd*)pkt);
        return 0;
    case RAW_MTYPE_BSUB:
        raw_bsub_hton((struct raw_pkt_bsub*)pkt);
        return 0;
    case RAW_MTYPE_BSMP:
        raw_bsmp_hton((struct raw_pkt_bsmp*)pkt);
        return 0;
    default:
        return -1;
    }
}

static void raw_req_ntoh(struct raw_pkt_cmd *req)
{
    struct raw_cmd_req *rcmd = raw_req(req);
    raw_ph_ntoh(&req->ph);
    rcmd->r_id = ntohs(raw_r_id(req));
    rcmd->r_val = ntohl(raw_r_val(req));
}

static void raw_res_ntoh(struct raw_pkt_cmd *res)
{
    struct raw_cmd_res *rcmd = raw_res(res);
    raw_ph_ntoh(&res->ph);
    rcmd->r_id = ntohs(raw_r_id(res));
    rcmd->r_val = ntohl(raw_r_val(res));
}

static int raw_bsub_ntoh(struct raw_pkt_bsub *bsub)
{
    bsub->b_cookie_h = ntohl(bsub->b_cookie_h);
    bsub->b_cookie_l = ntohl(bsub->b_cookie_l);
    bsub->b_id = ntohl(bsub->b_id);
    bsub->b_sidx = ntohl(bsub->b_sidx);
    bsub->b_chip_live = ntohl(bsub->b_chip_live);
    for (size_t i = 0; i < RAW_BSUB_NSAMP; i++) {
        bsub->b_samps[i] = raw_samp_ntoh(bsub->b_samps[i]);
    }
    bsub->b_gpio = ntohs(bsub->b_gpio);
    return 0;
}

static void raw_bsmp_ntoh(struct raw_pkt_bsmp *bsmp)
{
    bsmp->b_cookie_h = ntohl(bsmp->b_cookie_h);
    bsmp->b_cookie_l = ntohl(bsmp->b_cookie_l);
    bsmp->b_id = ntohl(bsmp->b_id);
    bsmp->b_sidx = ntohl(bsmp->b_sidx);
    bsmp->b_chip_live = ntohl(bsmp->b_chip_live);
    for (size_t i = 0; i < RAW_BSMP_NSAMP; i++) {
        bsmp->b_samps[i] = raw_samp_ntoh(bsmp->b_samps[i]);
    }
}

int raw_pkt_ntoh(void *pkt)
{
    struct raw_pkt_header *ph = pkt;
    raw_ph_ntoh(ph);
    if ((ph->_p_magic != RAW_PKT_HEADER_MAGIC ||
         ph->p_proto_vers > RAW_PKT_HEADER_PROTO_VERS)) {
        return -1;
    }
    switch (raw_mtype(pkt)) {
    case RAW_MTYPE_REQ:
        raw_req_ntoh((struct raw_pkt_cmd*)pkt);
        return 0;
    case RAW_MTYPE_RES:
        raw_res_ntoh((struct raw_pkt_cmd*)pkt);
        return 0;
    case RAW_MTYPE_ERR:
        raw_err_ntoh((struct raw_pkt_cmd*)pkt);
        return 0;
    case RAW_MTYPE_BSUB:
        raw_bsub_hton((struct raw_pkt_bsub*)pkt);
        return 0;
    case RAW_MTYPE_BSMP:
        raw_bsmp_hton((struct raw_pkt_bsmp*)pkt);
        return 0;
    default:
        return -1;
    }
}

ssize_t raw_cmd_send(int sockfd, struct raw_pkt_cmd *pkt, int flags)
{
    if (raw_pkt_hton(pkt) == -1) {
        errno = EINVAL;
        return -1;
    }
    size_t len = sizeof(struct raw_pkt_cmd);
    ssize_t ret = send(sockfd, pkt, len, flags);
    if (ret == -1) {
        return ret;
    } else if ((size_t)ret < len) {
        /* We want raw_cmd_send() to work atomically on raw_pkt_cmds,
         * but we didn't send enough data. Eventually, we'll do
         * something smarter, but just fail for now. */
        /* TODO be smarter */
        log_WARNING("not enough data sent (%zd/%zu B)", ret, len);
        errno = EIO;
        return -1;
    }
    return ret;
}

ssize_t raw_cmd_recv(int sockfd, struct raw_pkt_cmd *pkt, int flags)
{
    uint8_t expected_mtype = raw_mtype(pkt);
    size_t len = sizeof(struct raw_pkt_cmd);
    ssize_t ret = recv(sockfd, pkt, len, flags);
    if (ret <= 0) {
        return ret;
    } else if ((size_t)ret < len) {
        /* See comment in raw_cmd_send(). */
        /* TODO be smarter */
        log_WARNING("%s: not enough data received (%zd/%zu B)",
                    __func__, ret, len);
        errno = EIO;
        return -1;
    }
    raw_pkt_ntoh(pkt);
    if (pkt->ph._p_magic != RAW_PKT_HEADER_MAGIC) {
        errno = EPROTO;
        return -1;
    } else if (expected_mtype != 0 && expected_mtype != raw_mtype(pkt)) {
        errno = EIO;
        return -1;
    }
    return ret;
}

ssize_t raw_bsub_recv(int sockfd, struct raw_pkt_bsub *bsub, int flags)
{
    int ret = recv(sockfd, bsub, sizeof(*bsub), flags);
    if (ret != 0 && raw_bsub_ntoh(bsub)) {
        errno = EPROTO;
        return -1;
    }
    return ret;
}

ssize_t raw_bsub_send(int sockfd, struct raw_pkt_bsub *bsub, int flags)
{
    if (raw_pkt_hton(bsub)) {
        return -1;
    }
    return send(sockfd, bsub, sizeof(*bsub), flags);
}

ssize_t raw_bsmp_recv(int sockfd, struct raw_pkt_bsmp *bsmp, int flags)
{
    int ret = recv(sockfd, bsmp, raw_bsmp_size(bsmp), flags);
    if (ret != 0) {
        raw_bsmp_ntoh(bsmp);
    }
    if (raw_mtype(bsmp) != RAW_MTYPE_BSMP) {
        errno = EPROTO;
        return -1;
    }
    return ret;
}

ssize_t raw_bsmp_send(int sockfd, struct raw_pkt_bsmp *bsmp, int flags)
{
    const size_t size = raw_bsmp_size(bsmp);
    raw_bsmp_hton(bsmp);
    return send(sockfd, bsmp, size, flags);
}

/*********************************************************************
 * Stringification
 */

#define CASE_STRINGIFY(c) c: return #c

const char* raw_r_type_str(uint8_t r_type)
{
    switch (r_type) {
    case CASE_STRINGIFY(RAW_RTYPE_ERR);
    case CASE_STRINGIFY(RAW_RTYPE_CENTRAL);
    case CASE_STRINGIFY(RAW_RTYPE_SATA);
    case CASE_STRINGIFY(RAW_RTYPE_DAQ);
    case CASE_STRINGIFY(RAW_RTYPE_UDP);
    case CASE_STRINGIFY(RAW_RTYPE_GPIO);
    default: return "<UNKNOWN_R_TYPE>";
    }
}

const char* raw_r_addr_str(uint8_t r_type, uint8_t r_addr)
{
    switch (r_type) {
    case RAW_RTYPE_ERR:
        switch (r_addr) {
        case CASE_STRINGIFY(RAW_RADDR_ERR_ERR0);
        default: return "<UNKNOWN_ERR_R_ADDR>";
        }
    case RAW_RTYPE_CENTRAL:
        switch (r_addr) {
        case CASE_STRINGIFY(RAW_RADDR_CENTRAL_ERR);
        case CASE_STRINGIFY(RAW_RADDR_CENTRAL_STATE);
        case CASE_STRINGIFY(RAW_RADDR_CENTRAL_EXP_CK_H);
        case CASE_STRINGIFY(RAW_RADDR_CENTRAL_EXP_CK_L);
        default: return "<UNKNOWN_CENTRAL_R_ADDR>";
        }
    case RAW_RTYPE_SATA:
        switch (r_addr) {
        case CASE_STRINGIFY(RAW_RADDR_SATA_ERR);
        case CASE_STRINGIFY(RAW_RADDR_SATA_ENABLE);
        case CASE_STRINGIFY(RAW_RADDR_SATA_DISK_ID);
        case CASE_STRINGIFY(RAW_RADDR_SATA_IO_PARAM);
        case CASE_STRINGIFY(RAW_RADDR_SATA_R_IDX);
        case CASE_STRINGIFY(RAW_RADDR_SATA_R_LEN);
        case CASE_STRINGIFY(RAW_RADDR_SATA_W_IDX);
        default: return "<UNKNOWN_SATA_R_ADDR>";
        }
    case RAW_RTYPE_DAQ:
        switch (r_addr) {
        case CASE_STRINGIFY(RAW_RADDR_DAQ_ERR);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_ENABLE);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_BSMP_START);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_BSMP_CURR);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_CHIP_ALIVE);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_CHIP_CMD);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_CHIP_SYNCH);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_FIFO_COUNT);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_FIFO_FLAGS);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_UDP_ENABLE);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_UDP_MODE);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_SATA_ENABLE);
        case RAW_RADDR_DAQ_BSUB0_CFG...RAW_RADDR_DAQ_BSUB31_CFG:
            /* TODO be smarter */
            return "RAW_RADDR_DAQ_BSUBx_CFG";

        default: return "<UNKNOWN_DAQ_R_ADDR>";
        }
    case RAW_RTYPE_UDP:
        switch (r_addr) {
        case CASE_STRINGIFY(RAW_RADDR_UDP_ERR);
        case CASE_STRINGIFY(RAW_RADDR_UDP_ENABLE);
        case CASE_STRINGIFY(RAW_RADDR_UDP_SRC_MAC_H);
        case CASE_STRINGIFY(RAW_RADDR_UDP_SRC_MAC_L);
        case CASE_STRINGIFY(RAW_RADDR_UDP_DST_MAC_H);
        case CASE_STRINGIFY(RAW_RADDR_UDP_DST_MAC_L);
        case CASE_STRINGIFY(RAW_RADDR_UDP_SRC_IP4);
        case CASE_STRINGIFY(RAW_RADDR_UDP_DST_IP4);
        case CASE_STRINGIFY(RAW_RADDR_UDP_SRC_IP4_PORT);
        case CASE_STRINGIFY(RAW_RADDR_UDP_DST_IP4_PORT);
        case CASE_STRINGIFY(RAW_RADDR_UDP_PKT_TX_COUNT);
        case CASE_STRINGIFY(RAW_RADDR_UDP_ETH_PKT_LEN);
        case CASE_STRINGIFY(RAW_RADDR_UDP_PAYLOAD_LEN);
        case CASE_STRINGIFY(RAW_RADDR_UDP_MODE);
        case CASE_STRINGIFY(RAW_RADDR_UDP_GIGE_STATUS);
        default: return "<UNKNOWN_UDP_R_ADDR>";
        }
    case RAW_RTYPE_GPIO:
        switch (r_addr) {
        case CASE_STRINGIFY(RAW_RADDR_GPIO_ERR);
        case CASE_STRINGIFY(RAW_RADDR_GPIO_READ);
        case CASE_STRINGIFY(RAW_RADDR_GPIO_WRITE);
        case CASE_STRINGIFY(RAW_RADDR_GPIO_STATE);
        default: return "<UNKNOWN_GPIO_R_ADDR>";
        }
    default: return "<UNKNOWN_R_ADDR>";
    }
}
