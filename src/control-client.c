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

#include "proto/control.pb-c.h"

#define LOCAL_DEBUG_LOGV 0

#if LOCAL_DEBUG_LOGV
#define LOCAL_DEBUG(...) log_DEBUG(__VA_ARGS__)
#else
#define LOCAL_DEBUG(...) ((void)0)
#endif

/* FIXME:
 *
 * - add timeouts when processing commands
 * - check responses request IDs and drop unexpected non-error responses
 * - send error to client on timeout?
 * - allow client to configure timeout?
 * - drop ongoing transaction on client closure
 */

/* Google says individual protocol buffers should be < 1 MB each:
 *
 * https://developers.google.com/protocol-buffers/docs/techniques#large-data
 *
 * So we might as well try to enforce reasonably good
 * behavior. Clients that send messages which are too long cause
 * protocol errors. */
#define CLIENT_CMD_MAX_SIZE (2 * 1024 * 1024)

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
    uint8_t c_cmd_arr[CLIENT_CMD_MAX_SIZE];
    uint8_t c_rsp_arr[CLIENT_CMD_MAX_SIZE];
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
    assert(len < CLIENT_CMD_MAX_SIZE); /* or WTF; honestly */
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
    priv->c_pbuf = c_pbuf;
    priv->c_cmdlen_buf = c_cmdlen_buf;
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
    if (cpriv->c_cmdlen > CLIENT_CMD_MAX_SIZE) {
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

static enum control_worker_why client_read(struct control_session *cs)
{
    enum control_worker_why ret = CONTROL_WHY_NONE;
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
    /* FIXME add smarts for other types of commands */
    default:
        CLIENT_RES_ERR_C_PROTO(cs, "unknown command type");
        break;
    }
}

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
    /* FIXME support new ControlCommand types here */
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
};

const struct control_ops *control_client_ops = &client_control_operations;
