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

    uint16_t req_id;            /* current raw_packets.h request ID */
};

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

/* FIXME replace uses of this function with robust error handling */
static void client_protocol_error(__unused struct control_session *cs,
                                  unsigned eproto)
{
    /* FIXME XXX signal an error or shut down the connection instead,
     * to prevent DoS attacks. */
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

/* For fresh connection */
static void client_reset_priv(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    control_must_lock(cs);
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
    control_must_unlock(cs);
}

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
    priv->req_id = 0;
    cs->cpriv = priv;
    client_reset_priv(cs);
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
    assert(cpriv);
    assert(cpriv->c_cmd == NULL);
    assert(cpriv->c_pbuf);
    assert(evbuffer_get_length(cpriv->c_pbuf) == 0);
    assert(evbuffer_get_length(cpriv->c_cmdlen_buf) == 0);
    assert(cpriv->c_cmdlen == CLIENT_CMDLEN_WAITING);
}

static int client_open(struct control_session *cs,
                       __unused evutil_socket_t control_sockfd)
{
    client_ensure_clean(cs);
    return 0;
}

static void client_close(__unused struct control_session *cs)
{
    /* FIXME
     *
     * Control session already notified worker about lost connection;
     * we need to make sure it's figured that out before cleaning up
     * our stuff. */
    assert(cs->cpriv);
    client_reset_priv(cs);
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
        client_protocol_error(cs, CLIENT_EPROTO_CMDLEN);
    }

    /* We've received a complete length prefix, so shove any
     * new/additional bits into cpriv->c_pbuf. */
    size_t pbuf_len = evbuffer_get_length(cpriv->c_pbuf);
    evbuffer_remove_buffer(evb, cpriv->c_pbuf, cpriv->c_cmdlen - pbuf_len);

 out:
    return (cpriv->c_cmdlen != CLIENT_CMDLEN_WAITING &&
            evbuffer_get_length(cpriv->c_pbuf) == (unsigned)cpriv->c_cmdlen);
}

static enum control_worker_why client_read(struct control_session *cs)
{
    /*
     * Try to pull an entire protocol buffer out of cs->dbev.
     */
    if (!client_got_entire_pbuf(cs)) {
        return CONTROL_WHY_NONE; /* Not enough data yet. */
    }

    /*
     * The entire protocol buffer has been received; unpack it.
     */
    control_must_lock(cs);
    struct client_priv *cpriv = cs->cpriv;
    size_t pbuf_len = evbuffer_get_length(cpriv->c_pbuf);
    size_t nrem = evbuffer_remove(cpriv->c_pbuf, cpriv->c_cmd_arr, pbuf_len);
    assert(nrem == pbuf_len);
    cpriv->c_cmd = control_command__unpack(NULL, pbuf_len, cpriv->c_cmd_arr);
    if (!cpriv->c_cmd) {
        /* Something's terribly wrong -- out of memory? */
        log_CRIT("can't unpack command protocol message; dying");
        control_must_unlock(cs);
        client_reset_priv(cs);
        return CONTROL_WHY_EXIT;
    }
    /* Command is unpacked; prepare to read another protocol buffer. */
    cpriv->c_cmdlen = CLIENT_CMDLEN_WAITING;
    assert(evbuffer_get_length(cpriv->c_pbuf) == 0);
    assert(evbuffer_get_length(cpriv->c_cmdlen_buf) == 0);
    control_must_unlock(cs);

    /*
     * Ready to wake the worker. Clients aren't allowed to send us
     * more than one command at a time, so reading another is a
     * protocol error.
     */
    if (client_got_entire_pbuf(cs)) {
        client_protocol_error(cs, CLIENT_EPROTO_2CMDS);
        assert(0);      /* client_protocol_error is currently fatal */
        return CONTROL_WHY_EXIT; /* appease GCC */
    } else {
        return CONTROL_WHY_CLIENT_CMD;
    }
}

static void client_err_no_dnode(struct control_session *cs)
{
    log_WARNING("%s: got client command, but no datanode is connected",
                __func__);
    struct client_priv *cpriv = cs->cpriv;
    ControlResErr crerr = CONTROL_RES_ERR__INIT;
    crerr.has_code = 1;
    crerr.code = CONTROL_RES_ERR__ERR_CODE__NO_DNODE;
    crerr.msg = "data node is not connected";
    ControlResponse cr = CONTROL_RESPONSE__INIT;
    cr.has_type = 1;
    cr.type = CONTROL_RESPONSE__TYPE__ERR;
    cr.err = &crerr;
    size_t len = control_response__get_packed_size(&cr);
    assert(len < CLIENT_CMD_MAX_SIZE); /* or WTF; honestly */
    size_t packed = control_response__pack(&cr, cpriv->c_rsp_arr);
    client_cmd_len_t clen = cmd_hton((client_cmd_len_t)packed);
    bufferevent_write(cs->cbev, &clen, CMDLEN_SIZE);
    bufferevent_write(cs->cbev, cpriv->c_rsp_arr, packed);
}

static void client_process_cmd(struct control_session *cs)
{
    log_DEBUG("%s: handling protocol message", __func__);
    /* All we currently support is RegisterIO */
    struct client_priv *cpriv = cs->cpriv;
    assert(cpriv->c_cmd->has_type);
    assert(cpriv->c_cmd->type == CONTROL_COMMAND__TYPE__REG_IO);
    assert(cpriv->c_cmd->reg_io);
    RegisterIO *reg_io = cpriv->c_cmd->reg_io;
    assert(reg_io->has_type);
    uint16_t reg_addr;
    switch (reg_io->type) {
    case REGISTER_IO__TYPE__ERR:
        if (!reg_io->has_err) {
            client_protocol_error(cs, CLIENT_EPROTO_PMSG);
        }
        reg_addr = reg_io->err;
        break;
    case REGISTER_IO__TYPE__CENTRAL:
        if (!reg_io->has_central) {
            client_protocol_error(cs, CLIENT_EPROTO_PMSG);
        }
        reg_addr = reg_io->central;
        break;
    case REGISTER_IO__TYPE__SATA:
        if (!reg_io->has_sata) {
            client_protocol_error(cs, CLIENT_EPROTO_PMSG);
        }
        reg_addr = reg_io->sata;
        break;
    case REGISTER_IO__TYPE__DAQ:
        if (!reg_io->has_daq) {
            client_protocol_error(cs, CLIENT_EPROTO_PMSG);
        }
        reg_addr = reg_io->daq;
        break;
    case REGISTER_IO__TYPE__UDP:
        if (!reg_io->has_udp) {
            client_protocol_error(cs, CLIENT_EPROTO_PMSG);
        }
        reg_addr = reg_io->udp;
        break;
    case REGISTER_IO__TYPE__GPIO:
        if (!reg_io->has_gpio) {
            client_protocol_error(cs, CLIENT_EPROTO_PMSG);
        }
        reg_addr = reg_io->gpio;
        break;
    default:
        client_protocol_error(cs, CLIENT_EPROTO_PMSG);
        break;
    }

    /* Inform the data node side that there's work to be done */
    struct raw_pkt_cmd *req_pkt = &cs->req_pkt;
    struct raw_cmd_req *req = raw_req(req_pkt);
    raw_packet_init(req_pkt, RAW_MTYPE_REQ, 0);
    req->r_id = cpriv->req_id++;
    req->r_type = reg_io->type;
    req->r_addr = reg_addr;
    raw_clear_flags(req_pkt, RAW_PFLAG_RIOD);
    if (reg_io->has_val) {
        req->r_val = reg_io->val;
        raw_set_flags(req_pkt, RAW_PFLAG_RIOD_W);
    } else {
        req->r_val = 0;
        raw_set_flags(req_pkt, RAW_PFLAG_RIOD_R);
    }
    cs->wake_why |= CONTROL_WHY_DNODE_REQ;
}

static void client_thread(struct control_session *cs)
{
    int handled = 0;
    struct client_priv *cpriv = cs->cpriv;

    if (cs->wake_why & CONTROL_WHY_CLIENT_CMD) {
        assert(cpriv->c_cmd);
        if (!cs->dbev) {
            client_err_no_dnode(cs);
        } else {
            client_process_cmd(cs);
        }
        control_command__free_unpacked(cpriv->c_cmd, NULL);
        cpriv->c_cmd = NULL;
        cs->wake_why &= ~CONTROL_WHY_CLIENT_CMD;
        handled = 1;
    }
    if (cs->wake_why & CONTROL_WHY_CLIENT_RES) {
        log_WARNING("%s: FIXME: just assuming client ordered RegisterIO",
                    __func__);
        struct raw_cmd_res *res = raw_res(&cs->res_pkt);
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
        size_t packed = control_response__pack(&cr, cpriv->c_rsp_arr);
        client_cmd_len_t clen = cmd_hton((client_cmd_len_t)packed);
        bufferevent_write(cs->cbev, &clen, CMDLEN_SIZE);
        bufferevent_write(cs->cbev, cpriv->c_rsp_arr, packed);
        cs->wake_why &= ~CONTROL_WHY_CLIENT_RES;
        handled = 1;
    }
    if (!handled) {
        log_WARNING("unhandled client wake; why=%d", (int)cs->wake_why);
    }
}

static const struct control_ops client_control_operations = {
    .cs_start = client_start,
    .cs_stop = client_stop,
    .cs_open = client_open,
    .cs_close = client_close,
    .cs_read = client_read,
    .cs_thread = client_thread,
};

const struct control_ops *control_client_ops = &client_control_operations;
