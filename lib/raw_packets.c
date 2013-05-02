/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

#include "raw_packets.h"

#include <errno.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "logging.h"

#define PACKET_HEADER_MAGIC      0x5A
#define PACKET_HEADER_PROTO_VERS 0x00

/*********************************************************************
 * Initialization and convenience
 */

void raw_packet_init(void *packet, uint8_t mtype, uint8_t flags)
{
    struct raw_pkt_header *ph = packet;
    ph->_p_magic = PACKET_HEADER_MAGIC;
    ph->p_proto_vers = PACKET_HEADER_PROTO_VERS;
    ph->p_mtype = mtype;
    ph->p_flags = flags;

    if (mtype == RAW_MTYPE_ERR) {
        struct raw_pkt_cmd *pkt = packet;
        memset(&pkt->p, 0, sizeof(struct raw_cmd_err));
    }
}

struct raw_pkt_bsub* raw_alloc_bsub(size_t nsamp)
{
    struct raw_pkt_bsub *ret = malloc(sizeof(struct raw_pkt_bsub) +
                                      nsamp * sizeof(raw_samp_t));
    if (ret) {
        raw_packet_init(ret, RAW_MTYPE_BSUB, 0);
        ret->b_nsamp = nsamp;
    }
    return ret;
}

void raw_pkt_copy(void *dst, const void *src)
{
    memcpy(dst, src, raw_pkt_size(src));
}

int raw_num_regs(uint8_t r_type)
{
    switch (r_type) {
    case RAW_RTYPE_TOP:
        return RAW_RADDR_TOP_NREGS;
    case RAW_RTYPE_SATA:
        return RAW_RADDR_SATA_NREGS;
    case RAW_RTYPE_DAQ:
        return RAW_RADDR_DAQ_NREGS;
    case RAW_RTYPE_UDP:
        return RAW_RADDR_UDP_NREGS;
    case RAW_RTYPE_EXP:
        return RAW_RADDR_EXP_NREGS;
    case RAW_RTYPE_ERR:
        return RAW_RADDR_ERR_NREGS;
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
        return raw_bsub_size(pkt);
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

static int raw_cmd_hton(struct raw_pkt_cmd *pkt)
{
    switch (raw_mtype(pkt)) {
    case RAW_MTYPE_REQ:
        raw_req_hton(pkt);
        return 0;
    case RAW_MTYPE_RES:
        raw_res_hton(pkt);
        return 0;
    case RAW_MTYPE_ERR:
        raw_err_hton(pkt);
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

static int raw_cmd_ntoh(struct raw_pkt_cmd *pkt)
{
    switch (raw_mtype(pkt)) {
    case RAW_MTYPE_REQ:
        raw_req_ntoh(pkt);
        return 0;
    case RAW_MTYPE_RES:
        raw_res_ntoh(pkt);
        return 0;
    case RAW_MTYPE_ERR:
        raw_err_ntoh(pkt);
        return 0;
    default:
        return -1;
    }
}

static void raw_bsub_hton(struct raw_pkt_bsub *bsub)
{
    raw_ph_hton(&bsub->ph);
    bsub->b_cookie_h = htonl(bsub->b_cookie_h);
    bsub->b_cookie_l = htonl(bsub->b_cookie_l);
    bsub->b_id = htonl(bsub->b_id);
    bsub->b_sidx = htonl(bsub->b_sidx);
    for (size_t i = 0; i < bsub->b_nsamp; i++) {
        bsub->b_samps[i] = raw_samp_hton(bsub->b_samps[i]);
    }
    bsub->b_nsamp = htonl(bsub->b_nsamp);
}

static void raw_bsub_ntoh(struct raw_pkt_bsub *bsub)
{
    raw_ph_ntoh(&bsub->ph);
    bsub->b_cookie_h = ntohl(bsub->b_cookie_h);
    bsub->b_cookie_l = ntohl(bsub->b_cookie_l);
    bsub->b_id = ntohl(bsub->b_id);
    bsub->b_sidx = ntohl(bsub->b_sidx);
    bsub->b_nsamp = ntohl(bsub->b_nsamp);
    for (size_t i = 0; i < bsub->b_nsamp; i++) {
        bsub->b_samps[i] = raw_samp_ntoh(bsub->b_samps[i]);
    }
}

static void raw_bsmp_hton(struct raw_pkt_bsmp *bsmp)
{
    raw_ph_hton(&bsmp->ph);
    bsmp->b_cookie_h = htonl(bsmp->b_cookie_h);
    bsmp->b_cookie_l = htonl(bsmp->b_cookie_l);
    bsmp->b_id = htonl(bsmp->b_id);
    bsmp->b_sidx = htonl(bsmp->b_sidx);
    bsmp->b_chip_live = htonl(bsmp->b_chip_live);
    for (size_t i = 0; i < raw_bsmp_nsamp(bsmp); i++) {
        bsmp->b_samps[i] = raw_samp_hton(bsmp->b_samps[i]);
    }
}

static void raw_bsmp_ntoh(struct raw_pkt_bsmp *bsmp)
{
    raw_ph_ntoh(&bsmp->ph);
    bsmp->b_cookie_h = ntohl(bsmp->b_cookie_h);
    bsmp->b_cookie_l = ntohl(bsmp->b_cookie_l);
    bsmp->b_id = ntohl(bsmp->b_id);
    bsmp->b_sidx = ntohl(bsmp->b_sidx);
    bsmp->b_chip_live = ntohl(bsmp->b_chip_live);
    for (size_t i = 0; i < raw_bsmp_nsamp(bsmp); i++) {
        bsmp->b_samps[i] = raw_samp_ntoh(bsmp->b_samps[i]);
    }
}

ssize_t raw_cmd_send(int sockfd, struct raw_pkt_cmd *pkt, int flags)
{
    if (raw_cmd_hton(pkt) == -1) {
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
    raw_cmd_ntoh(pkt);
    if (pkt->ph._p_magic != PACKET_HEADER_MAGIC) {
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
    size_t nsamp = bsub->b_nsamp;
    int ret = recv(sockfd, bsub, raw_bsub_size(bsub), flags);
    if (ret == -1) {
        return -1;
    }
    if (raw_mtype_ntoh(raw_mtype(bsub)) != RAW_MTYPE_BSUB) {
        errno = EPROTO;
        return -1;
    }
    if (ntohl(bsub->b_nsamp) > nsamp) {
        /* Caller's raw_pkt_bsub is too small; the following
         * raw_bsub_ntoh() will touch random memory. */
        errno = EINVAL;
        return -1;
    }
    raw_bsub_ntoh(bsub);
    return ret;
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

ssize_t raw_bsub_send(int sockfd, struct raw_pkt_bsub *bsub, int flags)
{
    const size_t size = raw_bsub_size(bsub);
    raw_bsub_hton(bsub);
    return send(sockfd, bsub, size, flags);
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
    case CASE_STRINGIFY(RAW_RTYPE_TOP);
    case CASE_STRINGIFY(RAW_RTYPE_SATA);
    case CASE_STRINGIFY(RAW_RTYPE_DAQ);
    case CASE_STRINGIFY(RAW_RTYPE_UDP);
    case CASE_STRINGIFY(RAW_RTYPE_EXP);
    default: return "<UNKNOWN_R_TYPE>";
    }
}

const char* raw_r_addr_str(uint8_t r_type, uint8_t r_addr)
{
    switch (r_type) {
    case RAW_RTYPE_ERR:
        switch (r_addr) {
        case CASE_STRINGIFY(RAW_RADDR_ERR_ERR0);
        default: return "<UNKNOWN_R_ADDR>";
        }
    case RAW_RTYPE_TOP:
        switch (r_addr) {
        case CASE_STRINGIFY(RAW_RADDR_TOP_ERR);
        case CASE_STRINGIFY(RAW_RADDR_TOP_STATE);
        case CASE_STRINGIFY(RAW_RADDR_TOP_EXP_CK_H);
        case CASE_STRINGIFY(RAW_RADDR_TOP_EXP_CK_L);
        case RAW_RADDR_TOP_BSUB_CH_MIN...RAW_RADDR_TOP_BSUB_CH_MAX:
            return "RAW_RADDR_TOP_BSUB_CH_<x>"; /* TODO be smarter */
        default: return "<UNKNOWN_R_ADDR>";
        }
    case RAW_RTYPE_SATA:
        switch (r_addr) {
        case CASE_STRINGIFY(RAW_RADDR_SATA_ERR);
        case CASE_STRINGIFY(RAW_RADDR_SATA_STATE);
        case CASE_STRINGIFY(RAW_RADDR_SATA_DISK_ID);
        case CASE_STRINGIFY(RAW_RADDR_SATA_IO_PARAM);
        case CASE_STRINGIFY(RAW_RADDR_SATA_R_IDX);
        case CASE_STRINGIFY(RAW_RADDR_SATA_R_LEN);
        case CASE_STRINGIFY(RAW_RADDR_SATA_W_IDX);
        default: return "<UNKNOWN_R_ADDR>";
        }
    case RAW_RTYPE_DAQ:
        switch (r_addr) {
        case CASE_STRINGIFY(RAW_RADDR_DAQ_ERR);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_STATE);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_BSMP_START);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_BSMP_CURR);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_CHIP_ALIVE);
        case CASE_STRINGIFY(RAW_RADDR_DAQ_CHIP_CMD);
        default: return "<UNKNOWN_R_ADDR>";
        }
    case RAW_RTYPE_UDP:
        switch (r_addr) {
        case CASE_STRINGIFY(RAW_RADDR_UDP_ERR);
        case CASE_STRINGIFY(RAW_RADDR_UDP_STATE);
        case CASE_STRINGIFY(RAW_RADDR_UDP_SRC_MAC_H);
        case CASE_STRINGIFY(RAW_RADDR_UDP_SRC_MAC_L);
        case CASE_STRINGIFY(RAW_RADDR_UDP_DST_MAC_H);
        case CASE_STRINGIFY(RAW_RADDR_UDP_DST_MAC_L);
        case CASE_STRINGIFY(RAW_RADDR_UDP_SRC_IP4);
        case CASE_STRINGIFY(RAW_RADDR_UDP_DST_IP4);
        case CASE_STRINGIFY(RAW_RADDR_UDP_SRC_IP4_PORT);
        case CASE_STRINGIFY(RAW_RADDR_UDP_DST_IP4_PORT);
        default: return "<UNKNOWN_R_ADDR>";
        }
    case RAW_RTYPE_EXP:
        switch (r_addr) {
        case CASE_STRINGIFY(RAW_RADDR_EXP_ERR);
        case CASE_STRINGIFY(RAW_RADDR_EXP_GPIOS);
        case CASE_STRINGIFY(RAW_RADDR_EXP_GPIO_STATE);
        default: return "<UNKNOWN_R_ADDR>";
        }
    default: return "<UNKNOWN_R_ADDR>";
    }
}
