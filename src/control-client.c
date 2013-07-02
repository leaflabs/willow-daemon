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

#include "control-client.h"
#include "control-private.h"

#include <stdlib.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "type_attrs.h"
#include "logging.h"
#include "raw_packets.h"
#include "sockutil.h"

#include "proto/control.pb-c.h"
#include "proto/data.pb-c.h"

#define LOCAL_DEBUG_LOGV 0

#if LOCAL_DEBUG_LOGV
#define LOCAL_DEBUG(...) log_DEBUG(__VA_ARGS__)
#else
#define LOCAL_DEBUG(...) ((void)0)
#endif

/* FIXME:
 *
 * - add timeouts when processing commands
 * - send error to client on timeout?
 * - allow client to configure timeout?
 * - drop ongoing transaction on client closure
 */

/* Client message length prefix type. Signed so -1 can mean "still
 * waiting to read length" */
typedef int32_t client_cmd_len_t;
#define CMDLEN_SIZE sizeof(client_cmd_len_t)
#define CLIENT_CMDLEN_WAITING (-1)

struct client_priv {
    ControlCommand *c_cmd; /* Latest unpacked protocol message, or
                            * NULL. Shared with worker thread. */
    ControlResponse *c_rsp;     /* Latest response to send, or NULL.
                                 * Worker thread only. */

    struct evbuffer *c_pbuf; /* buffers c_cmd protocol buffer while waiting */

    struct evbuffer *c_cmdlen_buf; /* buffers c_cmdlen while we're waiting */
    client_cmd_len_t c_cmdlen;     /* length of c_pbuf, NOT length of c_cmd */

    /* Allocate a command and response's worth of contiguous space at
     * client_start() time, rather than using e.g. evbuffer_pullup()
     * at each read(). */
    uint8_t c_cmd_arr[CONTROL_CMD_MAX_SIZE];
    uint8_t c_rsp_arr[CONTROL_CMD_MAX_SIZE];

    /* Similarly, keep buffers around for initializing and packing
     * data protocol messages. Touch these from the main thread
     * only. */
    uint32_t c_bsub_chips[RAW_BSUB_NSAMP];
    uint32_t c_bsub_chans[RAW_BSUB_NSAMP];
    uint32_t c_bsub_samps[RAW_BSUB_NSAMP];
    uint8_t c_data_pbuf_arr[CONTROL_CMD_MAX_SIZE];

    uint32_t debug_last_sub_idx;
};

/********************************************************************
 * Miscellaneous helpers
 */

/* Convert a client message length from network to host byte ordering */
static inline client_cmd_len_t cmd_ntoh(client_cmd_len_t net)
{
    return ntohl(net);
}

/* Convert client message length from host to network byte ordering */
static inline client_cmd_len_t cmd_hton(client_cmd_len_t host)
{
    return htonl(host);
}

#define CLIENT_EPROTO_CMDLEN 0
#define CLIENT_EPROTO_2CMDS  1
#define CLIENT_EPROTO_PMSG   2
#define CLIENT_EPROTO_MAX    3

static const char *client_eproto_str(unsigned eproto)
{
    static const char* strings[] = {
        [CLIENT_EPROTO_CMDLEN] = "command length too long",
        [CLIENT_EPROTO_2CMDS] = "too many commands on the wire",
        [CLIENT_EPROTO_PMSG] = "malformed protocol message",
        [CLIENT_EPROTO_MAX] = "unknown error",
    };
    if (eproto >= CLIENT_EPROTO_MAX) {
        eproto = CLIENT_EPROTO_MAX;
    }
    return strings[eproto];
}

static void client_fatal_protocol_error(__unused struct control_session *cs,
                                        unsigned eproto)
{
    /* FIXME XXX shut down the connection instead, to prevent DoS
     * attacks. */
    log_CRIT("client protocol error: %s", client_eproto_str(eproto));
    exit(EXIT_FAILURE);
}

/* NOT SYNCHRONIZED; do not call while worker thread is running.*/
static void client_free_priv(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    if (cpriv->c_cmd) {
        control_command__free_unpacked(cpriv->c_cmd, NULL);
    }
    if (cpriv->c_rsp) {
        control_response__free_unpacked(cpriv->c_rsp, NULL);
    }
    if (cpriv->c_pbuf) {
        evbuffer_free(cpriv->c_pbuf);
    }
    if (cpriv->c_cmdlen_buf) {
        evbuffer_free(cpriv->c_cmdlen_buf);
    }
    free(cpriv);
    cs->cpriv = NULL;
}

static inline void drain_evbuf(struct evbuffer *evb)
{
    if (evb) {
        evbuffer_drain(evb, evbuffer_get_length(evb));
    }
}

static void client_reset_state_locked(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    if (!cpriv) {
        return;
    }
    if (cpriv->c_cmd) {
        control_command__free_unpacked(cpriv->c_cmd, NULL);
    }
    cpriv->c_cmd = NULL;
    cpriv->c_cmdlen = CLIENT_CMDLEN_WAITING;
    if (cpriv->c_rsp) {
        control_response__free_unpacked(cpriv->c_rsp, NULL);
    }
    cpriv->c_rsp = NULL;
    drain_evbuf(cpriv->c_pbuf);
    drain_evbuf(cpriv->c_cmdlen_buf);
}

/* For fresh connection */
static void client_reset_state_unlocked(struct control_session *cs)
{
    control_must_lock(cs);
    client_reset_state_locked(cs);
    control_must_unlock(cs);
}

/********************************************************************
 * Conveniences for sending responses to client
 *
 * NOT SYNCHRONIZED; must be called with control session mutex locked.
 */

static void client_done_with_cmd(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    control_clear_transactions(cs, 1);
    assert(cpriv->c_cmd);
    control_command__free_unpacked(cpriv->c_cmd, NULL);
    cpriv->c_cmd = NULL;
}

static void client_send_response(struct control_session *cs,
                                 ControlResponse *cr)
{
    struct client_priv *cpriv = cs->cpriv;
    size_t len = control_response__get_packed_size(cr);
    assert(len < CONTROL_CMD_MAX_SIZE); /* or WTF; honestly */
    size_t packed = control_response__pack(cr, cpriv->c_rsp_arr);
    client_cmd_len_t clen = cmd_hton((client_cmd_len_t)packed);
    bufferevent_write(cs->cbev, &clen, CMDLEN_SIZE);
    bufferevent_write(cs->cbev, cpriv->c_rsp_arr, packed);
    client_done_with_cmd(cs);
}

static void client_send_err(struct control_session *cs,
                            ControlResErr__ErrCode code,
                            char *msg)
{
    ControlResErr crerr = CONTROL_RES_ERR__INIT;
    crerr.has_code = 1;
    crerr.code = code;
    crerr.msg = msg;
    ControlResponse cr = CONTROL_RESPONSE__INIT;
    cr.has_type = 1;
    cr.type = CONTROL_RESPONSE__TYPE__ERR;
    cr.err = &crerr;
    client_send_response(cs, &cr);
}

static void client_send_success(struct control_session *cs)
{
    ControlResponse cr = CONTROL_RESPONSE__INIT;
    cr.has_type = 1;
    cr.type = CONTROL_RESPONSE__TYPE__SUCCESS;
    client_send_response(cs, &cr);
}

#define CLIENT_RES_ERR_NO_DNODE(cs) do {                                \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__NO_DNODE,        \
                        "not connected to data node");                  \
    } while (0)

#define CLIENT_RES_ERR_DAEMON(cs, msg) do {                             \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__DAEMON,          \
                        "internal daemon error: " msg);                 \
 } while (0)

#define CLIENT_RES_ERR_C_PROTO(cs, msg) do {                           \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__C_PROTO,        \
                        "client protocol error: " msg); } while (0)

#define CLIENT_RES_ERR_D_PROTO(cs, msg) do {                           \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__D_PROTO,        \
                        "data node protocol error: " msg); } while (0)

#define CLIENT_RES_ERR_DNODE(cs, msg) do {                           \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__DNODE,        \
                        "data node error: " msg); } while (0)

/********************************************************************
 * Main thread control_ops callbacks
 */

static int client_start(struct control_session *cs)
{
    struct client_priv *priv = NULL;
    struct evbuffer *c_pbuf = NULL;
    struct evbuffer *c_cmdlen_buf = NULL;

    priv = malloc(sizeof(struct client_priv));
    if (!priv) {
        goto bail;
    }
    c_pbuf = evbuffer_new();
    if (!c_pbuf) {
        goto bail;
    }
    c_cmdlen_buf = evbuffer_new();
    if (!c_cmdlen_buf) {
        goto bail;
    }

    priv->c_cmd = NULL;
    priv->c_rsp = NULL;
    priv->c_pbuf = c_pbuf;
    priv->c_cmdlen_buf = c_cmdlen_buf;
    priv->debug_last_sub_idx = 0;
    cs->cpriv = priv;
    client_reset_state_locked(cs); /* worker isn't started; don't
                                    * bother locking */
    return 0;

 bail:
    if (priv) {
        free(priv);
    }
    if (c_pbuf) {
        evbuffer_free(c_pbuf);
    }
    if (c_cmdlen_buf) {
        evbuffer_free(c_cmdlen_buf);
    }
    return -1;
}

static void client_stop(struct control_session *cs)
{
    client_reset_state_locked(cs); /* worker thread isn't running */
    if (cs->cpriv) {
        client_free_priv(cs);
    }
}

static void client_ensure_clean(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    control_must_lock(cs);
    assert(cpriv);
    assert(cpriv->c_cmd == NULL);
    assert(cpriv->c_pbuf);
    assert(evbuffer_get_length(cpriv->c_pbuf) == 0);
    assert(evbuffer_get_length(cpriv->c_cmdlen_buf) == 0);
    assert(cpriv->c_cmdlen == CLIENT_CMDLEN_WAITING);
    assert(cs->ctl_txns == NULL);
    assert(cs->ctl_cur_txn == -1);
    control_must_unlock(cs);
}

static int client_open(struct control_session *cs,
                       __unused evutil_socket_t control_sockfd)
{
    client_ensure_clean(cs);
    return 0;
}

static void client_close(struct control_session *cs)
{
    assert(cs->cpriv);
    client_reset_state_unlocked(cs);
    client_ensure_clean(cs);
}

static int client_got_entire_pbuf(struct control_session *cs)
{
    struct evbuffer *evb = bufferevent_get_input(cs->cbev);
    struct client_priv *cpriv = cs->cpriv;

    /* If waiting for a length prefix, buffer it into
     * cpriv->c_cmdlen_buf. If that fills the buffer, unpack it into
     * cs->c_cmdlen. */
    if (cpriv->c_cmdlen == CLIENT_CMDLEN_WAITING) {
        size_t cmdlen_buflen = evbuffer_get_length(cpriv->c_cmdlen_buf);
        evbuffer_remove_buffer(evb, cpriv->c_cmdlen_buf,
                               CMDLEN_SIZE - cmdlen_buflen);
        assert(evbuffer_get_length(cpriv->c_cmdlen_buf) <= CMDLEN_SIZE);
        if (evbuffer_get_length(cpriv->c_cmdlen_buf) < CMDLEN_SIZE) {
            goto out;
        } else { /* evbuffer_get_length(cs->c_cmdlen_buf) == CMDLEN_SIZE */
            evbuffer_remove(cpriv->c_cmdlen_buf, &cpriv->c_cmdlen,
                            CMDLEN_SIZE);
            cpriv->c_cmdlen = cmd_ntoh(cpriv->c_cmdlen);
        }
    }

    /* Sanity-check the received protocol buffer length. */
    if (cpriv->c_cmdlen > CONTROL_CMD_MAX_SIZE) {
        client_fatal_protocol_error(cs, CLIENT_EPROTO_CMDLEN);
    }

    /* We've received a complete length prefix, so shove any
     * new/additional bits into cpriv->c_pbuf. */
    size_t pbuf_len = evbuffer_get_length(cpriv->c_pbuf);
    evbuffer_remove_buffer(evb, cpriv->c_pbuf, cpriv->c_cmdlen - pbuf_len);

 out:
    return (cpriv->c_cmdlen != CLIENT_CMDLEN_WAITING &&
            evbuffer_get_length(cpriv->c_pbuf) == (unsigned)cpriv->c_cmdlen);
}

/* NOT SYNCHRONIZED */
static void client_reset_for_next_pbuf(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    cpriv->c_cmdlen = CLIENT_CMDLEN_WAITING;
    assert(evbuffer_get_length(cpriv->c_pbuf) == 0);
    assert(evbuffer_get_length(cpriv->c_cmdlen_buf) == 0);
}

static int client_read(struct control_session *cs)
{
    int ret = CONTROL_WHY_NONE;
    struct client_priv *cpriv = cs->cpriv;

    control_must_lock(cs);

    /*
     * Try to pull an entire protocol buffer out of cs->dbev.
     */
    if (!client_got_entire_pbuf(cs)) {
        goto done;
    }

    if (cpriv->c_cmd || cs->ctl_txns) {
        /* There's an existing command we're still dealing with; the
         * client shouldn't have sent us a new one. */
        CLIENT_RES_ERR_C_PROTO(cs,
                               "command received while another "
                               "is being processed");
        goto done;
    }

    /*
     * The entire protocol buffer has been received; unpack it.
     */
    size_t pbuf_len = evbuffer_get_length(cpriv->c_pbuf);
    size_t nrem = evbuffer_remove(cpriv->c_pbuf, cpriv->c_cmd_arr, pbuf_len);
    assert(nrem == pbuf_len);
    cpriv->c_cmd = control_command__unpack(NULL, pbuf_len, cpriv->c_cmd_arr);
    if (!cpriv->c_cmd) {
        CLIENT_RES_ERR_DAEMON(cs, "can't unpack client command");
        goto done;
    }
    client_reset_for_next_pbuf(cs);

    /*
     * Ready to wake the worker.
     */
    if (client_got_entire_pbuf(cs)) {
        /* Clients aren't allowed to send us more than one command at
         * a time, so the fact that we just read another is a protocol
         * error.
         *
         * Ensuring that there isn't another protocol buffer waiting
         * in cs->cbev at this time implies that this callback will
         * get invoked again when the next one finishes arriving. By
         * sending an error now, we don't get stuck with a complete
         * command sitting in an evbuffer and libevent having no
         * reason to invoke a callback to process it. */
        CLIENT_RES_ERR_C_PROTO(cs, "two commands sent at once; both dropped");
        client_reset_for_next_pbuf(cs);
        goto done;
    } else {
        ret = CONTROL_WHY_CLIENT_CMD;
        goto done;
    }

 done:
    control_must_unlock(cs);
    return ret;
}

static int client_data(struct control_session *cs, struct sockaddr *addr)
{
    struct client_priv *cpriv = cs->cpriv;
    uint8_t *pkt_buf = cs->dpbuf.iov_base;
    if (raw_pkt_ntoh(pkt_buf)) {
        log_INFO("dropping malformed data node packet");
        return -1;
    }
    uint8_t mtype = raw_mtype(pkt_buf);
    uint8_t pflags = raw_pflags(pkt_buf);
    if (mtype == RAW_MTYPE_BSUB) {
        struct raw_pkt_bsub *bsub = (struct raw_pkt_bsub*)pkt_buf;
        DnodeSample dnsample = DNODE_SAMPLE__INIT;
        BoardSubsample msg_bsub = BOARD_SUBSAMPLE__INIT;
        msg_bsub.has_is_live = 1;
        msg_bsub.is_live = !!(pflags & RAW_PFLAG_B_LIVE);
        msg_bsub.has_is_last = 1;
        msg_bsub.is_last = !!(pflags & RAW_PFLAG_B_LAST);
        msg_bsub.has_exp_cookie = 1;
        msg_bsub.exp_cookie = raw_exp_cookie(bsub);
        msg_bsub.has_board_id = 1;
        msg_bsub.board_id = bsub->b_id;
        msg_bsub.has_samp_idx = 1;
        msg_bsub.samp_idx = bsub->b_sidx;
        msg_bsub.has_chip_live = 1;
        msg_bsub.chip_live = bsub->b_chip_live;
        msg_bsub.n_chips = RAW_BSUB_NSAMP;
        msg_bsub.chips = cpriv->c_bsub_chips;
        msg_bsub.n_channels = RAW_BSUB_NSAMP;
        msg_bsub.channels = cpriv->c_bsub_chans;
        msg_bsub.n_samples = RAW_BSUB_NSAMP;
        msg_bsub.samples = cpriv->c_bsub_samps;
        for (size_t i = 0; i < RAW_BSUB_NSAMP; i++) {
            msg_bsub.chips[i] = bsub->b_cfg[i].bs_chip;
            msg_bsub.channels[i] = bsub->b_cfg[i].bs_chan;
            msg_bsub.samples[i] = bsub->b_samps[i];
        }
        msg_bsub.has_gpio = 1;
        msg_bsub.gpio = bsub->b_gpio;
        msg_bsub.has_dac_channel = 1;
        msg_bsub.dac_channel = bsub->b_dac_cfg;
        msg_bsub.has_dac_value = 1;
        msg_bsub.dac_value = bsub->b_dac;
        dnsample.has_type = 1;
        dnsample.type = DNODE_SAMPLE__TYPE__SUBSAMPLE;
        dnsample.subsample = &msg_bsub;
        size_t dnsample_psize = dnode_sample__get_packed_size(&dnsample);
        if (dnsample_psize > CONTROL_CMD_MAX_SIZE) {
            log_WARNING("packed subsample buffer size %zu exceeds "
                        "preallocated buffer size %d; "
                        "falling back on malloc().",
                        dnsample_psize, CONTROL_CMD_MAX_SIZE);
            uint8_t *out = malloc(dnsample_psize);
            if (!out) {
                log_ERR("out of memory");
                return -1;
            }
            dnode_sample__pack(&dnsample, out);
            int ret = sendto(cs->ddatafd, out, dnsample_psize, 0,
                            addr, sockutil_addrlen(addr));
            free(out);
            return ret;
        }
        dnode_sample__pack(&dnsample, cpriv->c_data_pbuf_arr);
        ssize_t s = sendto(cs->ddatafd, cpriv->c_data_pbuf_arr, dnsample_psize,
                           0, addr, sockutil_addrlen(addr));

        if (cpriv->debug_last_sub_idx != msg_bsub.samp_idx - 1) {
            log_DEBUG("bsub GAP: %u",
                      bsub->b_sidx - 1 - cpriv->debug_last_sub_idx);
        }
        cpriv->debug_last_sub_idx = bsub->b_sidx;

        return s == (ssize_t)dnsample_psize ? 0 : -1;
    } else if (mtype == RAW_MTYPE_BSMP) {
        log_WARNING("%s: board sample handling is unimplemented", __func__);
        return -1;
    }
    assert(0);
    return -1;
}

/********************************************************************
 * Worker thread (ControlCommand handling)
 */

/*
 * Conveniences for dealing with transactions.
 *
 * NB: all r_id values get set by control_set_transactions().
 */

__unused
static inline void client_err_r(struct control_txn *txn, uint8_t r_addr)
{
    raw_req_init(&txn->req_pkt, RAW_PFLAG_RIOD_R,
                 0, RAW_RTYPE_ERR, r_addr, 0);
}
__unused
static inline void client_err_w(struct control_txn *txn,
                                uint8_t r_addr, uint32_t r_val)
{
    raw_req_init(&txn->req_pkt, RAW_PFLAG_RIOD_W,
                 0, RAW_RTYPE_ERR, r_addr, r_val);
}
__unused
static inline void client_central_r(struct control_txn *txn, uint8_t r_addr)
{
    raw_req_init(&txn->req_pkt, RAW_PFLAG_RIOD_R,
                 0, RAW_RTYPE_CENTRAL, r_addr, 0);
}
__unused
static inline void client_central_w(struct control_txn *txn,
                                    uint8_t r_addr, uint32_t r_val)
{
    raw_req_init(&txn->req_pkt, RAW_PFLAG_RIOD_W,
                 0, RAW_RTYPE_CENTRAL, r_addr, r_val);
}
__unused
static inline void client_sata_r(struct control_txn *txn, uint8_t r_addr)
{
    raw_req_init(&txn->req_pkt, RAW_PFLAG_RIOD_R,
                 0, RAW_RTYPE_SATA, r_addr, 0);
}
__unused
static inline void client_sata_w(struct control_txn *txn,
                                 uint8_t r_addr, uint32_t r_val)
{
    raw_req_init(&txn->req_pkt, RAW_PFLAG_RIOD_W,
                 0, RAW_RTYPE_SATA, r_addr, r_val);
}
__unused
static inline void client_daq_r(struct control_txn *txn, uint8_t r_addr)
{
    raw_req_init(&txn->req_pkt, RAW_PFLAG_RIOD_R,
                 0, RAW_RTYPE_DAQ, r_addr, 0);
}
__unused
static inline void client_daq_w(struct control_txn *txn,
                                uint8_t r_addr, uint32_t r_val)
{
    raw_req_init(&txn->req_pkt, RAW_PFLAG_RIOD_W,
                 0, RAW_RTYPE_DAQ, r_addr, r_val);
}
__unused
static inline void client_udp_r(struct control_txn *txn, uint8_t r_addr)
{
    raw_req_init(&txn->req_pkt, RAW_PFLAG_RIOD_R,
                 0, RAW_RTYPE_UDP, r_addr, 0);
}
__unused
static inline void client_udp_w(struct control_txn *txn,
                                uint8_t r_addr, uint32_t r_val)
{
    raw_req_init(&txn->req_pkt, RAW_PFLAG_RIOD_W,
                 0, RAW_RTYPE_UDP, r_addr, r_val);
}
__unused
static inline void client_gpio_r(struct control_txn *txn, uint8_t r_addr)
{
    raw_req_init(&txn->req_pkt, RAW_PFLAG_RIOD_R,
                 0, RAW_RTYPE_GPIO, r_addr, 0);
}
__unused
static inline void client_gpio_w(struct control_txn *txn,
                                 uint8_t r_addr, uint32_t r_val)
{
    raw_req_init(&txn->req_pkt, RAW_PFLAG_RIOD_W,
                 0, RAW_RTYPE_GPIO, r_addr, r_val);
}

static int client_last_txn_succeeded(struct control_session *cs)
{
    if (!cs->ctl_txns) {
        log_WARNING("attempt to check success of nonexistent control_txn");
        return -1;
    }
    assert(cs->ctl_cur_txn != -1);
    struct control_txn *txn = &cs->ctl_txns[cs->ctl_cur_txn];
    struct raw_pkt_cmd *req_pkt = &txn->req_pkt;
    struct raw_cmd_req *req = raw_req(req_pkt);
    struct raw_pkt_cmd *res_pkt = &txn->res_pkt;
    struct raw_cmd_res *res = raw_res(res_pkt);
    /* Check for explicit error response */
    if (raw_pkt_is_err(res_pkt)) {
        LOCAL_DEBUG("got error result");
        return 0;
    }
    /* On a write, check that result matches the request exactly
     * (i.e., that the resulting r_id, r_type, r_addr, and r_val match
     * requested ones).  */
    if (raw_req_is_write(req_pkt) && (memcmp(req, res, sizeof(*req)) != 0)) {
        LOCAL_DEBUG("write raw_cmd_req doesn't match raw_cmd_res");
        if (req->r_id != res->r_id) {
            LOCAL_DEBUG("req->r_id=%u, res->r_id=%u", req->r_id, res->r_id);
        } else if (req->r_type != res->r_type) {
            LOCAL_DEBUG("req->r_type=%u, res->r_type=%u", req->r_type,
                        res->r_type);
        } else if (req->r_addr != res->r_addr) {
            LOCAL_DEBUG("req->r_addr=%u, res->r_addr=%u", req->r_addr,
                        res->r_addr);
        } else if (req->r_val != res->r_val) {
            LOCAL_DEBUG("req->r_val=%u, res->r_val=%u", req->r_val,
                        res->r_val);
        } else {
            LOCAL_DEBUG("nvm, it's marti's fault");
        }
        return 0;
    }
    /* On a read, just check r_id, r_type, and r_addr */
    if (raw_req_is_read(req_pkt) &&
        (req->r_id != res->r_id || req->r_type != res->r_type ||
         req->r_addr != res->r_addr)) {
        LOCAL_DEBUG("read raw_cmd_req doesn't match enough of raw_cmd_res");
        return 0;
    }
    return 1;
}

/*
 * Request processing
 */

/* Handle a client command with embedded RegisterIO */
static void client_process_cmd_regio(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    RegisterIO *reg_io = cpriv->c_cmd->reg_io;

    if (!reg_io) {
        CLIENT_RES_ERR_C_PROTO(cs,
                               "missing reg_io field in command specifying "
                               "register I/O");
        return;
    }
    if (!reg_io->has_type) {
        CLIENT_RES_ERR_C_PROTO(cs, "missing RegisterIO type field");
        return;
    }

    /* A little evil macro to save typing. */
    uint16_t reg_addr;
#define REG_IO_CASE(lcase, ucase)                                       \
    REGISTER_IO__TYPE__ ## ucase:                                       \
        if (!reg_io->has_ ## lcase) {                                   \
            CLIENT_RES_ERR_C_PROTO(cs,                                 \
                                   "missing " #lcase " register address"); \
            return;                                                     \
        }                                                               \
        reg_addr = reg_io->lcase;                                       \
        break

    switch (reg_io->type) {
    case REG_IO_CASE(err, ERR);
    case REG_IO_CASE(central, CENTRAL);
    case REG_IO_CASE(sata, SATA);
    case REG_IO_CASE(daq, DAQ);
    case REG_IO_CASE(udp, UDP);
    case REG_IO_CASE(gpio, GPIO);
    default:
        CLIENT_RES_ERR_C_PROTO(cs, "no address field set in RegisterIO");
        return;
    }
#undef REG_IO_CASE

    struct control_txn *txn = malloc(sizeof(struct control_txn));
    if (!txn) {
        CLIENT_RES_ERR_DAEMON(cs, "out of memory");
        return;
    }
    uint8_t ioflag = reg_io->has_val ? RAW_PFLAG_RIOD_W : RAW_PFLAG_RIOD_R;
    uint32_t ioval = reg_io->has_val ? reg_io->val : 0;
    raw_req_init(&txn->req_pkt, ioflag, 0, reg_io->type, reg_addr, ioval);
    control_set_transactions(cs, txn, 1, 1);
    cs->wake_why |= CONTROL_WHY_DNODE_TXN;
}

static uint32_t client_get_data_addr4(struct control_session *cs,
                                      uint32_t *s_addr)
{
    struct sockaddr_storage sas;
    struct sockaddr_in *saddr = (struct sockaddr_in*)&sas;
    socklen_t sas_len = sizeof(sas);
    if (sockutil_get_iface_addr(cs->ddataif, AF_INET,
                                (struct sockaddr*)&sas, &sas_len)) {
        log_WARNING("can't read dnode data socket address");
        return -1;
    }
    assert(sas.ss_family == AF_INET);
    *s_addr = htonl(saddr->sin_addr.s_addr);
    return 0;
}

static int client_get_data_mac48(struct control_session *cs,
                                 uint8_t mac48[6])
{
    size_t len = 6;
    int ret = sockutil_get_iface_hwaddr(cs->ddataif, mac48, &len);
    assert(len == 6);
    return ret;
}

static void client_process_cmd_stream(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    ControlCmdStream *stream = cpriv->c_cmd->stream;
    struct sockaddr_in *caddr = (struct sockaddr_in*)&cs->caddr;
    struct sockaddr_in *dnaddr = (struct sockaddr_in*)&cs->dnaddr;

    if (!stream) {
        CLIENT_RES_ERR_C_PROTO(cs, "missing stream field");
        return;
    }
    int has_addr = stream->has_dest_udp_addr4;
    int has_port = stream->has_dest_udp_port;
    if (has_addr ^ has_port) {
        CLIENT_RES_ERR_C_PROTO(cs,
                               "neither or both of UDP address/port "
                               "must be set");
        return;
    }
    if (has_port && (stream->dest_udp_port > UINT16_MAX)) {
        CLIENT_RES_ERR_C_PROTO(cs, "specified port is out of range");
        return;
    }

    /*
     * Prepare client side of main thread conversion callback
     */
    memset(&caddr->sin_zero, 0, sizeof(caddr->sin_zero));
    /* Reconfigure address/port if necessary */
    if (has_addr) {
        caddr->sin_port = htons((uint16_t)stream->dest_udp_port);
    }
    if (has_port) {
        caddr->sin_addr.s_addr = htonl(stream->dest_udp_addr4);
    }
    /* If this is just a reconfigure command, then we're done here;
     * the main thread will pick up the change at next callback. */
    if (!stream->has_enable) {
        client_send_success(cs);
        return;
    }

    /*
     * Prepare transactions
     */
    const size_t max_txns = 15;
    struct control_txn *txns = malloc(max_txns * sizeof(struct control_txn));
    size_t txno = 0;
    if (!txns) {
        CLIENT_RES_ERR_DAEMON(cs, "out of memory");
        return;
    }
    if (stream->enable) {
        /* Get the daemon data socket's IPv4 and MAC48 addresses, which we
         * need to initialize dnode registers. */
        uint32_t dsock_ipv4;
        uint8_t dsock_m48[6];
        if ((client_get_data_addr4(cs, &dsock_ipv4) ||
             client_get_data_mac48(cs, dsock_m48))) {
            CLIENT_RES_ERR_DAEMON(cs, "internal network error");
            return;
        }
        uint32_t m48h = (((uint32_t)dsock_m48[0] << 8) |
                         (uint32_t)dsock_m48[1]);
        uint32_t m48l = (((uint32_t)dsock_m48[2] << 24) |
                         ((uint32_t)dsock_m48[3] << 16) |
                         ((uint32_t)dsock_m48[4] << 8) |
                         (uint32_t)dsock_m48[5]);
        /* Read the data node's UDP IPv4 address and port. */
        client_udp_r(txns + txno++, RAW_RADDR_UDP_SRC_IP4);
        client_udp_r(txns + txno++, RAW_RADDR_UDP_SRC_IP4_PORT);
        /* Set UDP IPv4 destination register. */
        client_udp_w(txns + txno++, RAW_RADDR_UDP_DST_IP4, dsock_ipv4);
        /* Set UDP MAC destination registers */
        client_udp_w(txns + txno++, RAW_RADDR_UDP_DST_MAC_H, m48h);
        client_udp_w(txns + txno++, RAW_RADDR_UDP_DST_MAC_L, m48l);
        /* Write 0 (STOP) to UDP and DAQ enable registers */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_UDP_ENABLE, 0);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_ENABLE, 0);
        client_udp_w(txns + txno++, RAW_RADDR_UDP_ENABLE, 0);
        /* Toggle reset line by writing 1/0 to DAQ FIFO flags register
         * (bring reset line high/low) */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_FIFO_FLAGS, 1);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_FIFO_FLAGS, 0);
        /* Setup payload length (packet type) for UDP core */
        /* 0 means board sub-samples (not full) */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_UDP_MODE, 0);
        /* Set UDP module to stream from DAQ (not SATA) */
        client_udp_w(txns + txno++, RAW_RADDR_UDP_MODE, 0); // 0x0D==13; 0
        /* Enable UDP module */
        client_udp_w(txns + txno++, RAW_RADDR_UDP_ENABLE, 1);
        /* Enable DAQ module */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_UDP_ENABLE, 1);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_ENABLE, 1);
    } else {
        /* We only enable on success, from the result callback handler. */
        caddr->sin_family = AF_UNSPEC;
        dnaddr->sin_family = AF_UNSPEC;

        /* Write 0 (STOP) to DAQ and UDP enable registers */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_ENABLE, 0);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_UDP_ENABLE, 0);
        client_udp_w(txns + txno++, RAW_RADDR_UDP_ENABLE, 0);
        /* Toggle reset line by writing 1/0 to DAQ FIFO flags register
         * (bring reset line high/low) */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_FIFO_FLAGS, 1);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_FIFO_FLAGS, 0);
    }

    /*
     * Get data node side to start running the transactions
     */
    assert(txno <= max_txns);
    control_set_transactions(cs, txns, txno, 1);
    cs->wake_why |= CONTROL_WHY_DNODE_TXN;
}

static void client_process_cmd(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    ControlCommand *cmd = cpriv->c_cmd;
    if (!cmd->has_type) {
        CLIENT_RES_ERR_C_PROTO(cs, "missing type field in command");
        return;
    }

    log_DEBUG("%s: handling protocol message, type %d", __func__, cmd->type);

    switch (cmd->type) {
    case CONTROL_COMMAND__TYPE__REG_IO:
        client_process_cmd_regio(cs);
        break;
    case CONTROL_COMMAND__TYPE__STREAM:
        client_process_cmd_stream(cs);
        break;
    default:
        CLIENT_RES_ERR_C_PROTO(cs, "unknown command type");
        break;
    }
}

/*
 * Result processing
 */

static void client_process_res_regio(struct control_session *cs)
{
    struct control_txn *txn = &cs->ctl_txns[cs->ctl_cur_txn];
    struct raw_pkt_cmd *req_pkt = &txn->req_pkt, *res_pkt = &txn->res_pkt;
    struct raw_cmd_req *req = raw_req(req_pkt);
    struct raw_cmd_res *res = raw_res(res_pkt);

    /* If the response doesn't match the request, something's wrong */
    if (req->r_id != res->r_id) {
        log_ERR("got response r_id %u, expected %u", res->r_id, req->r_id);
        CLIENT_RES_ERR_D_PROTO(cs, "request/response ID mismatch");
        return;
    }

    RegisterIO reg_io = REGISTER_IO__INIT;
    reg_io.has_type = 1;
    reg_io.type = res->r_type;
#if (RAW_RTYPE_NTYPES - 1) != RAW_RTYPE_GPIO /* future-proofing */
#error "changes to RAW_RTYPE_* require client code updates"
#endif
    switch (res->r_type) {
    case RAW_RTYPE_ERR:
        reg_io.has_err = 1;
        reg_io.err = res->r_type;
        break;
    case RAW_RTYPE_CENTRAL:
        reg_io.has_central = 1;
        reg_io.central = res->r_type;
        break;
    case RAW_RTYPE_SATA:
        reg_io.has_sata = 1;
        reg_io.sata = res->r_type;
        break;
    case RAW_RTYPE_DAQ:
        reg_io.has_daq = 1;
        reg_io.daq = res->r_type;
        break;
    case RAW_RTYPE_UDP:
        reg_io.has_udp = 1;
        reg_io.udp = res->r_type;
        break;
    case RAW_RTYPE_GPIO:
        reg_io.has_gpio = 1;
        reg_io.gpio = res->r_type;
        break;
    default:
        log_ERR("unhandled RAW_RTYPE: %d", res->r_type);
        assert(0);
        return;
    }
    reg_io.has_val = 1;
    reg_io.val = res->r_val;
    ControlResponse cr = CONTROL_RESPONSE__INIT;
    cr.has_type = 1;
    cr.type = CONTROL_RESPONSE__TYPE__REG_IO;
    cr.reg_io = &reg_io;
    client_send_response(cs, &cr);
}

static void client_process_res_stream(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    ControlCmdStream *stream = cpriv->c_cmd->stream;
    struct sockaddr_in *caddr = (struct sockaddr_in*)&cs->caddr;
    struct sockaddr_in *dnaddr = (struct sockaddr_in*)&cs->dnaddr;

    /*
     * On failure, report error to client; they'll need to clean up
     */
    if (!client_last_txn_succeeded(cs)) {
        log_WARNING("transaction %zd/%zu failed processing ControlCmdStream",
                    cs->ctl_cur_txn, cs->ctl_n_txns);
        CLIENT_RES_ERR_DNODE(cs, "failed I/O transaction");
        return;
    }

    /*
     * Deal with any register values we needed to read.
     */
    if (stream->has_enable && stream->enable) {
        /* When enabling, we read the UDP IPv4 address and port registers. */
        struct raw_cmd_res *res = ctxn_res(cs->ctl_txns + cs->ctl_cur_txn);
        if (res->r_type == RAW_RTYPE_UDP) {
            if (res->r_addr == RAW_RADDR_UDP_SRC_IP4) {
                log_DEBUG("data node UDP source IPv4 address is %u.%u.%u.%u",
                          (res->r_val >> 24) & 0xFF,
                          (res->r_val >> 16) & 0xFF,
                          (res->r_val >> 8) & 0xFF,
                          res->r_val & 0xFF);
                dnaddr->sin_addr.s_addr = htonl(res->r_val);
                memset(&dnaddr->sin_zero, 0, sizeof(dnaddr->sin_zero));
            }
            if (res->r_addr == RAW_RADDR_UDP_SRC_IP4_PORT) {
                if (res->r_val > UINT16_MAX) {
                    log_WARNING("data node source IPv4 port %u is invalid",
                                res->r_val);
                    CLIENT_RES_ERR_DNODE(cs, "invalid data port specified");
                    return;
                }
                log_DEBUG("data node source UDP port is %u",
                          (uint16_t)res->r_val);
                dnaddr->sin_port = htons((uint16_t)res->r_val);
            }
        }
    }

    /*
     * OK, that last transaction was a success. If there are more to
     * come, keep going.
     */
    cs->ctl_cur_txn++;
    if ((size_t)cs->ctl_cur_txn != cs->ctl_n_txns) {
        cs->wake_why |= CONTROL_WHY_DNODE_TXN;
        return;
    }

    /*
     * That's the last transaction. Finish up and send the success
     * result.
     */
    if (stream->has_enable && stream->enable) {
        caddr->sin_family = AF_INET;
        dnaddr->sin_family = AF_INET;
    }
    client_send_success(cs);
}

static void client_process_res(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    /* Result packets should only occur when a transaction is
     * ongoing. It's the data node receive callback's job to
     * filter unexpected ones out for us. */
    assert(cs->ctl_txns && cs->ctl_cur_txn >= 0 &&
           (size_t)cs->ctl_cur_txn < cs->ctl_n_txns);
    assert(cpriv->c_cmd->has_type);
    switch (cpriv->c_cmd->type) {
    case CONTROL_COMMAND__TYPE__REG_IO:
        client_process_res_regio(cs);
        break;
    case CONTROL_COMMAND__TYPE__STREAM:
        client_process_res_stream(cs);
        break;
    default:
        log_ERR("got result for unhandled command type; ignoring it");
        break;
    }
}

static void client_process_err(__unused struct control_session *cs)
{
    log_ERR("%s: FIXME; unimplemented", __func__);
    exit(EXIT_FAILURE);
}

#define CLIENT_WHY_WAKE \
    (CONTROL_WHY_CLIENT_CMD | CONTROL_WHY_CLIENT_RES | CONTROL_WHY_CLIENT_ERR)
static void client_thread(struct control_session *cs)
{
    if (!(cs->wake_why & CLIENT_WHY_WAKE)) {
        log_WARNING("unexpected client wake; why=%d", (int)cs->wake_why);
        return;
    }
    if (cs->wake_why & CONTROL_WHY_CLIENT_CMD) {
        /* There should be no ongoing transactions */
        assert(!cs->ctl_txns);

        if (!cs->dbev) {
            CLIENT_RES_ERR_NO_DNODE(cs);
        } else {
            client_process_cmd(cs);
        }
        cs->wake_why &= ~CONTROL_WHY_CLIENT_CMD;
    }
    if (cs->wake_why & CONTROL_WHY_CLIENT_RES) {
        client_process_res(cs);
        cs->wake_why &= ~CONTROL_WHY_CLIENT_RES;
    }
    if (cs->wake_why & CONTROL_WHY_CLIENT_ERR) {
        client_process_err(cs);
        cs->wake_why &= ~CONTROL_WHY_CLIENT_ERR;
    }
}

/********************************************************************
 * control_ops
 */

static const struct control_ops client_control_operations = {
    .cs_start = client_start,
    .cs_stop = client_stop,
    .cs_open = client_open,
    .cs_close = client_close,
    .cs_read = client_read,
    .cs_thread = client_thread,
    .cs_data = client_data,
};

const struct control_ops *control_client_ops = &client_control_operations;
