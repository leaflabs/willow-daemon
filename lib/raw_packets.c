/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

#include "raw_packets.h"

#include <errno.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

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
    return send(sockfd, pkt, sizeof(struct raw_pkt_cmd), flags);
}

ssize_t raw_cmd_recv(int sockfd, struct raw_pkt_cmd *pkt, int flags)
{
    uint8_t expected_mtype = raw_mtype(pkt);
    int ret = recv(sockfd, pkt, sizeof(struct raw_pkt_cmd), flags);
    if (ret == -1) {
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
