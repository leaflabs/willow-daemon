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

#include "sample.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <event2/event.h>
#include <event2/util.h>

#include "logging.h"
#include "raw_packets.h"
#include "sockutil.h"
#include "type_attrs.h"
#include "proto/control.pb-c.h"
#include "proto/data.pb-c.h"

static void sample_ddatafd_callback(evutil_socket_t, short, void*);

union sample_packet {
    struct raw_pkt_bsub bsub;
    struct raw_pkt_bsmp bsmp;
};

#define SAMPLE_PBUF_ARR_SIZE (1024 * 1024)
struct sample_session {
    struct event_base *base;
    unsigned ddataif; /* Daemon data socket interface number; see
                       * <net/if.h>.  Set during control_new().
                       *
                       * Treat as constant. */
    evutil_socket_t ddatafd; /* Daemon data socket, open entire session.
                              *
                              * Main thread only. */

    struct iovec dpktbuf; /* Points to raw packet buffer for ddatafd.
                           * Main thread only. */

    /* Buffers for initializing and packing data protocol
     * messages. Main thread only. */
    uint32_t c_bsub_chips[RAW_BSUB_NSAMP];
    uint32_t c_bsub_chans[RAW_BSUB_NSAMP];
    uint32_t c_bsub_samps[RAW_BSUB_NSAMP];
    uint8_t *c_sample_pbuf_arr;

    /* Data socket event */
    struct event *ddataevt;

    pthread_mutex_t smpl_mtx;   /* Sample mutex. Protects following fields. */

    /* The following fields are shared with worker threads, and are
     * protected by smpl_mtx: */
    struct sockaddr_storage dnaddr; /* Data node address; receive
                                     * subsamples from here only. If
                                     * unset, .ss_family==AF_UNSPEC. */
    struct sockaddr_storage caddr; /* Client address; forward
                                    * subsamples to here. If unset,
                                    * .ss_family==AF_UNSPEC. */
    int forward_subs;  /* If true, we forward subsamples from data
                        * node to client. */

    uint32_t debug_last_sub_idx;
};

/*
 * pthreads helpers
 *
 * TODO abstract out what's in common with control.c
 */

static void
sample_fatal_err(const char *message, int code) /* code==-1 for "no code" */
{
    const char *msg = message ? message : "";
    const char *msgsep = message ? ": " : "";
    if (code > 0) {
        log_CRIT("fatal error (%d) in sample session%s%s", code, msgsep, msg);
    } else {
        log_CRIT("fatal error in sample session%s%s", msgsep, msg);
    }
    exit(EXIT_FAILURE);
}

static void sample_must_lock(struct sample_session *smpl)
{
    int en = pthread_mutex_lock(&smpl->smpl_mtx);
    if (en) {
        sample_fatal_err("can't lock sample_session", en);
    }
}

static void sample_must_unlock(struct sample_session *smpl)
{
    int en = pthread_mutex_unlock(&smpl->smpl_mtx);
    if (en) {
        sample_fatal_err("can't unlock sample_session", en);
    }
}

/*
 * Public API
 */

static void sample_init(struct sample_session *smpl)
{
    smpl->base = NULL;
    smpl->ddataif = 0;
    smpl->ddatafd = -1;
    smpl->ddataevt = NULL;
    smpl->dpktbuf.iov_base = NULL;
    smpl->dpktbuf.iov_len = 0;
    smpl->c_sample_pbuf_arr = NULL;
    smpl->dnaddr.ss_family = AF_UNSPEC;
    smpl->caddr.ss_family = AF_UNSPEC;
    smpl->forward_subs = 0;
    smpl->debug_last_sub_idx = 0;
}

struct sample_session *sample_new(struct event_base *base,
                                  unsigned iface,
                                  uint16_t port)
{
    int mtx_en = 0;
    struct sample_session *smpl = malloc(sizeof(struct sample_session));
    if (!smpl) {
        return NULL;
    }
    sample_init(smpl);
    mtx_en = pthread_mutex_init(&smpl->smpl_mtx, NULL);
    if (mtx_en) {
        log_ERR("thread error while initializing sample session");
        free(smpl);
        return NULL;
    }

    smpl->base = base;
    smpl->ddataif = iface;
    smpl->ddatafd = sockutil_get_udp_socket(port);
    if (smpl->ddatafd == -1) {
        log_ERR("can't create data socket");
        goto fail;
    }
    if (evutil_make_socket_nonblocking(smpl->ddatafd) == -1) {
        log_ERR("data socket doesn't support nonblocking I/O");
        goto fail;
    }
    smpl->dpktbuf.iov_base = malloc(sizeof(union sample_packet));
    if (!smpl->dpktbuf.iov_base) {
        goto fail;
    }
    smpl->dpktbuf.iov_len = sizeof(union sample_packet);
    smpl->c_sample_pbuf_arr = malloc(SAMPLE_PBUF_ARR_SIZE);
    if (!smpl->c_sample_pbuf_arr) {
        goto fail;
    }
    smpl->ddataevt = event_new(base, smpl->ddatafd, EV_READ | EV_PERSIST,
                               sample_ddatafd_callback, smpl);
    if (!smpl->ddataevt) {
        log_ERR("can't create data socket event");
        goto fail;
    }
    if (event_add(smpl->ddataevt, NULL)) {
        goto fail;
    }
    return smpl;

 fail:
    sample_free(smpl);
    return NULL;
}

void sample_free(struct sample_session *smpl)
{
    if (smpl->ddataevt) {
        event_free(smpl->ddataevt);
    }
    free(smpl->c_sample_pbuf_arr);
    free(smpl->dpktbuf.iov_base);
    if (smpl->ddatafd != -1 && evutil_closesocket(smpl->ddatafd)) {
        log_ERR("can't close data socket");
    }
    pthread_mutex_destroy(&smpl->smpl_mtx);
    free(smpl);
}

int sample_get_saddr(struct sample_session *smpl, int af,
                     struct sockaddr *addr,
                     socklen_t *addrlen)
{
    int ret;
    ret = sockutil_get_iface_addr(smpl->ddataif, af, addr, addrlen);
    return ret;
}

int sample_get_mac48(struct sample_session *smpl, uint8_t mac48[6])
{
    size_t len = 6;
    int ret = sockutil_get_iface_hwaddr(smpl->ddataif, mac48, &len);
    assert(len == 6);
    return ret;
}

/* NOT SYNCHRONIZED */
static struct sockaddr_storage* sample_addr(struct sample_session *smpl,
                                            enum sample_addr what)
{
    return (what == SAMPLE_ADDR_CLIENT ? &smpl->caddr :
            what == SAMPLE_ADDR_DNODE ? &smpl->dnaddr :
            NULL);
}

int sample_get_addr(struct sample_session *smpl,
                    struct sockaddr *addr, socklen_t *addrlen,
                    enum sample_addr what)
{
    int ret = 0;
    sample_must_lock(smpl);
    struct sockaddr_storage *src = sample_addr(smpl, what);
    if (!src || src->ss_family == AF_UNSPEC) {
        ret = -1;
        goto out;
    }
    socklen_t srclen = sockutil_addrlen((struct sockaddr*)src);
    if (*addrlen < srclen) {
        ret = -1;
        goto out;
    }
    memcpy(addr, src, srclen);
 out:
    sample_must_unlock(smpl);
    return ret;
}

static void sample_log_set_addr(struct sockaddr *addr, enum sample_addr what)
{
    if (addr->sa_family != AF_INET) {
        log_DEBUG("%s: can't print non-AF_INET addr", __func__);
    }
    struct sockaddr_in *addrin = (struct sockaddr_in*)addr;
    char addrp[INET6_ADDRSTRLEN + INET_ADDRSTRLEN];
    if (evutil_inet_ntop(AF_INET, &addrin->sin_addr, addrp, sizeof(addrp))) {
        log_DEBUG("%s sample address:port is %s:%u",
                  what == SAMPLE_ADDR_CLIENT ? "client" : "data node",
                  addrp, ntohs(addrin->sin_port));
    }
}

int sample_set_addr(struct sample_session *smpl,
                    struct sockaddr *addr, enum sample_addr what)
{
    int ret = 0;
    sample_must_lock(smpl);
    struct sockaddr_storage *dst = sample_addr(smpl, what);
    if (!dst) {
        ret = -1;
        goto out;
    }
    memcpy(dst, addr, sockutil_addrlen(addr));
    sample_log_set_addr(addr, what);
 out:
    sample_must_unlock(smpl);
    return ret;
}

/* NOT SYNCHRONIZED */
static int sample_enable_subsamples(struct sample_session *smpl)
{
    if (smpl->dnaddr.ss_family == AF_UNSPEC ||
        smpl->caddr.ss_family == AF_UNSPEC) {
        return -1;
    }
    smpl->forward_subs = 1;
    return 0;
}

/* NOT SYNCHRONIZED */
static int sample_disable_subsamples(struct sample_session *smpl)
{
    smpl->forward_subs = 0;
    return 0;
}

int sample_cfg_subsamples(struct sample_session *smpl, int enable)
{
    int ret;
    sample_must_lock(smpl);
    ret = (enable ?
           sample_enable_subsamples(smpl) :
           sample_disable_subsamples(smpl));
    sample_must_unlock(smpl);
    if (!ret) {
        log_DEBUG("%s subsample forwarding", enable ? "enabled" : "disabled");
    }
    return ret;
}

/*
 * libevent subsample conversion callback
 */

/* NOT SYNCHRONIZED */
static int sample_get_dnode_data(struct sample_session *smpl,
                                 struct sockaddr *dnaddr)
{
    struct iovec *iov = &smpl->dpktbuf;
    struct sockaddr_storage sas;
    ssize_t s;
    assert(iov->iov_base);
    while (1) {
        socklen_t sas_len = sizeof(sas);
        s = recvfrom(smpl->ddatafd, iov->iov_base, iov->iov_len, 0,
                     (struct sockaddr*)&sas, &sas_len);
        if (s == -1) {
            switch (errno) {
#if EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:   /* fall through */
#endif
            case EAGAIN:
                log_WARNING("%s: spurious call; invoked with no data to read",
                            __func__);
                return -1;
            case EINTR:
                continue;
            default:
                log_WARNING("%s: error: %m", __func__);
                return -1;
            }
        }
        break;
    }
    if ((size_t)s > iov->iov_len) {
        log_WARNING("truncated read getting sample from data node");
        return -1;
    }
    if (sas.ss_family != AF_INET && sas.ss_family != AF_INET6) {
        log_WARNING("data packet has unexpected remote address family %d",
                    sas.ss_family);
        return -1;
    }
    if (!sockutil_addr_eq(dnaddr, (struct sockaddr*)&sas, 0)) {
        log_DEBUG("ignoring data packet from unexpected address");
        return -1;
    }
    return 0;
}

static void sample_init_pmsg_from_bsub(BoardSubsample *msg_bsub,
                                       struct raw_pkt_bsub *bsub)
{
    uint8_t pflags = raw_pflags(bsub);
    msg_bsub->has_is_live = 1;
    msg_bsub->is_live = !!(pflags & RAW_PFLAG_B_LIVE);
    msg_bsub->has_is_last = 1;
    msg_bsub->is_last = !!(pflags & RAW_PFLAG_B_LAST);
    msg_bsub->has_exp_cookie = 1;
    msg_bsub->exp_cookie = raw_exp_cookie(bsub);
    msg_bsub->has_board_id = 1;
    msg_bsub->board_id = bsub->b_id;
    msg_bsub->has_samp_idx = 1;
    msg_bsub->samp_idx = bsub->b_sidx;
    msg_bsub->has_chip_live = 1;
    msg_bsub->chip_live = bsub->b_chip_live;
    msg_bsub->n_chips = RAW_BSUB_NSAMP;
    msg_bsub->n_channels = RAW_BSUB_NSAMP;
    msg_bsub->n_samples = RAW_BSUB_NSAMP;
    for (size_t i = 0; i < RAW_BSUB_NSAMP; i++) {
        msg_bsub->chips[i] = bsub->b_cfg[i].bs_chip;
        msg_bsub->channels[i] = bsub->b_cfg[i].bs_chan;
        msg_bsub->samples[i] = bsub->b_samps[i];
    }
    msg_bsub->has_gpio = 1;
    msg_bsub->gpio = bsub->b_gpio;
    msg_bsub->has_dac_channel = 1;
    msg_bsub->dac_channel = bsub->b_dac_cfg;
    msg_bsub->has_dac_value = 1;
    msg_bsub->dac_value = bsub->b_dac;
}

/* NOT SYNCHRONIZED */
static int sample_pack_and_ship_pmsg(struct sample_session *smpl,
                                     DnodeSample *dnsample,
                                     struct sockaddr *caddr)
{
    size_t dnsample_psize = dnode_sample__get_packed_size(dnsample);
    if (dnsample_psize > SAMPLE_PBUF_ARR_SIZE) {
        log_WARNING("packed subsample buffer size %zu exceeds "
                    "preallocated buffer size %d; "
                    "falling back on malloc().",
                    dnsample_psize, SAMPLE_PBUF_ARR_SIZE);
        uint8_t *out = malloc(dnsample_psize);
        if (!out) {
            log_ERR("out of memory");
            return -1;
        }
        dnode_sample__pack(dnsample, out);
        int ret = sendto(smpl->ddatafd, out, dnsample_psize, 0,
                         caddr, sockutil_addrlen(caddr));
        free(out);
        return ret;
    }
    dnode_sample__pack(dnsample, smpl->c_sample_pbuf_arr);
    ssize_t s = sendto(smpl->ddatafd, smpl->c_sample_pbuf_arr,
                       dnsample_psize, 0, caddr, sockutil_addrlen(caddr));

    return s == (ssize_t)dnsample_psize ? 0 : -1;
}

/* NOT SYNCHRONIZED */
static int sample_convert_and_ship_subsample(struct sample_session *smpl,
                                             struct sockaddr *caddr)
{
    uint8_t *pkt_buf = smpl->dpktbuf.iov_base;
    if (raw_pkt_ntoh(pkt_buf)) {
        log_INFO("dropping malformed data node packet");
        return -1;
    }
    uint8_t mtype = raw_mtype(pkt_buf);
    if (mtype != RAW_MTYPE_BSUB) {
        log_DEBUG("unexpected message type %s (%u) received on data socket",
                  raw_mtype_str(mtype), mtype);
        return -1;
    }
    BoardSubsample msg_bsub = BOARD_SUBSAMPLE__INIT;
    msg_bsub.chips = smpl->c_bsub_chips;
    msg_bsub.channels = smpl->c_bsub_chans;
    msg_bsub.samples = smpl->c_bsub_samps;
    DnodeSample dnsample = DNODE_SAMPLE__INIT;
    sample_init_pmsg_from_bsub(&msg_bsub, (struct raw_pkt_bsub*)pkt_buf);
    dnsample.subsample = &msg_bsub;
    dnsample.has_type = 1;
    dnsample.type = DNODE_SAMPLE__TYPE__SUBSAMPLE;
    uint32_t idx_gap = msg_bsub.samp_idx - smpl->debug_last_sub_idx - 1;
    if (idx_gap) {
        log_DEBUG("bsub GAP: %u", idx_gap);
    }
    smpl->debug_last_sub_idx = msg_bsub.samp_idx;
    return sample_pack_and_ship_pmsg(smpl, &dnsample, caddr);
}

static void sample_ddatafd_callback(evutil_socket_t ddatafd, short events,
                                    void *smplvp)
{
    struct sample_session *smpl = smplvp;
    assert(smpl->ddatafd == ddatafd);
    assert(events & EV_READ);

    sample_must_lock(smpl);
    struct sockaddr *dnaddr = (struct sockaddr*)&smpl->dnaddr;
    struct sockaddr *caddr = (struct sockaddr*)&smpl->caddr;

    /* Throw away unwanted data. */
    int expecting_data = (smpl->forward_subs &&
                          dnaddr->sa_family != AF_UNSPEC &&
                          caddr->sa_family != AF_UNSPEC);
    if (!expecting_data) {
        log_DEBUG("ignoring unwanted activity on data socket");
        recv(smpl->ddatafd, NULL, 0, 0);
        goto out;
    }

    /* Fill the data node sample packet buffer  */
    if (sample_get_dnode_data(smpl, dnaddr)) {
        log_DEBUG("%s: can't get data packet from data node", __func__);
        recv(smpl->ddatafd, NULL, 0, 0);
        goto out;
    }

    /* Convert and ship the buffer with the client callback */
    if (sample_convert_and_ship_subsample(smpl, caddr)) {
        log_DEBUG("%s: can't forward data node subsample to client", __func__);
    }
 out:
    sample_must_unlock(smpl);
}

