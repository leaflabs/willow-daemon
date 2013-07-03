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

#include "control-dnode.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "control-private.h"
#include "logging.h"
#include "raw_packets.h"
#include "sockutil.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>

struct dnode_priv {
    struct evbuffer *d_rbuf;    /* Buffers control session ->req_pkt */
};

union dnode_sample {
    struct raw_pkt_bsub bsub;
    struct raw_pkt_bsmp bsmp;
};

/* NOT SYNCHRONIZED */
static void dnode_free_priv(struct control_session *cs)
{
    if (!cs->dpriv) {
        return;
    }

    struct dnode_priv *dpriv = cs->dpriv;
    if (dpriv->d_rbuf) {
        evbuffer_free(dpriv->d_rbuf);
    }
    free(dpriv);
    cs->dpriv = NULL;
}

static void dnode_reset_state_locked(struct control_session *cs)
{
    struct dnode_priv *dpriv = cs->dpriv;
    evbuffer_drain(dpriv->d_rbuf, evbuffer_get_length(dpriv->d_rbuf));
}

static void dnode_reset_state_unlocked(struct control_session *cs)
{
    control_must_lock(cs);
    dnode_reset_state_locked(cs);
    control_must_unlock(cs);
}

static int dnode_start(struct control_session *cs)
{
    struct dnode_priv *priv = NULL;
    struct evbuffer *d_rbuf = NULL;

    priv = malloc(sizeof(struct dnode_priv));
    if (!priv) {
        goto bail;
    }
    d_rbuf = evbuffer_new();
    if (!d_rbuf) {
        goto bail;
    }

    priv->d_rbuf = d_rbuf;
    cs->dpriv = priv;
    dnode_reset_state_locked(cs); /* worker thread isn't running */
    return 0;

 bail:
    if (d_rbuf) {
        evbuffer_free(d_rbuf);
    }
    if (priv) {
        free(priv);
    }
    return -1;
}

static void dnode_stop(struct control_session *cs)
{
    dnode_free_priv(cs);
}

static void dnode_ensure_clean(struct control_session *cs)
{
    struct dnode_priv *dpriv = cs->dpriv;
    assert(dpriv->d_rbuf);
    assert(evbuffer_get_length(dpriv->d_rbuf) == 0);
    assert(cs->dpbuf.iov_base == NULL && cs->dpbuf.iov_len == 0);
}

static int dnode_open(struct control_session *cs,
                      __unused evutil_socket_t control_sockfd)
{
    dnode_ensure_clean(cs);
    cs->dpbuf.iov_base = malloc(sizeof(union dnode_sample));
    if (!cs->dpbuf.iov_base) {
        return -1;
    }
    cs->dpbuf.iov_len = sizeof(union dnode_sample);
    return 0;
}

static void dnode_close(struct control_session *cs)
{
    free(cs->dpbuf.iov_base);
    cs->dpbuf.iov_base = NULL;
    cs->dpbuf.iov_len = 0;
    dnode_reset_state_unlocked(cs);
    dnode_ensure_clean(cs);
}

static int dnode_got_entire_pkt(struct control_session *cs,
                                struct raw_pkt_cmd *pkt)
{
    struct evbuffer *evb = bufferevent_get_input(cs->dbev);
    struct dnode_priv *dpriv = cs->dpriv;
    int ret = 0;
    size_t cmdsize = sizeof(struct raw_pkt_cmd);

    control_must_lock(cs);
    size_t d_rbuf_len = evbuffer_get_length(dpriv->d_rbuf);
    if (d_rbuf_len < cmdsize) {
        evbuffer_remove_buffer(evb, dpriv->d_rbuf, cmdsize - d_rbuf_len);
    }
    assert(evbuffer_get_length(dpriv->d_rbuf) <= cmdsize);
    ret = evbuffer_get_length(dpriv->d_rbuf) == cmdsize;
    if (!ret) {
        goto done;
    }
    evbuffer_remove(dpriv->d_rbuf, pkt, cmdsize);
    if (raw_pkt_ntoh(pkt) == -1) {
        log_WARNING("ignoring malformed data node packet");
        ret = 0;
        goto done;
    }
    switch (raw_mtype(pkt)) {
    case RAW_MTYPE_RES:
        break;
    case RAW_MTYPE_ERR:
        break;
    default:
        log_WARNING("ignoring unexpected data node command packet "
                    "(not response or error)");
        ret = 0;
        break;
    }
 done:
    control_must_unlock(cs);
    return ret;
}

static int dnode_read(struct control_session *cs)
{
    int ret = CONTROL_WHY_NONE;
    struct raw_pkt_cmd pkt;
    while (dnode_got_entire_pkt(cs, &pkt)) {
        uint8_t mtype = raw_mtype(&pkt);
        switch (mtype) {
        case RAW_MTYPE_RES:
            if (ret & CONTROL_WHY_CLIENT_RES) {
                log_DEBUG("ignoring second result packet");
                continue;
            }
            if (!cs->ctl_txns) {
                log_DEBUG("ignoring dnode result outside of transaction");
                continue;
            }
            if (raw_pkt_is_err(&pkt)) {
                log_INFO("received error response packet from data node");
                log_DEBUG("flags 0x%x iserror=%d mod=%s add=%s",
                          raw_pflags(&pkt),
                          raw_mtype(&pkt)==RAW_MTYPE_ERR,
                          raw_r_type_str(raw_r_type(&pkt)),
                          raw_r_addr_str(raw_r_type(&pkt), raw_r_addr(&pkt))
                          );
            }
            control_must_lock(cs);
            memcpy(&cs->ctl_txns[cs->ctl_cur_txn].res_pkt, &pkt, sizeof(pkt));
            control_must_unlock(cs);
            ret |= CONTROL_WHY_CLIENT_RES;
            break;
        case RAW_MTYPE_ERR:
            if (ret & CONTROL_WHY_CLIENT_ERR) {
                /* Error packets don't contain any extra information,
                 * so there's no use flagging or logging this
                 * twice. */
                continue;
            }
            log_INFO("received error packet from data node");
            ret |= CONTROL_WHY_CLIENT_ERR;
            break;
        default:
            /* Can't happen */
            log_EMERG("%s: internal error", __func__);
            assert(0);
            return CONTROL_WHY_EXIT;
        }
    }
    return ret;
}

static void dnode_thread(struct control_session *cs)
{
    /* We should only wake up when the client handler has a request
     * for us to forward to the data node. */
    if (!(cs->wake_why & CONTROL_WHY_DNODE_TXN)) {
        log_ERR("dnode thread handler woke up unexpectedly");
        return;
    }
    assert(cs->ctl_txns && cs->ctl_n_txns && cs->ctl_cur_txn >= 0 &&
           (size_t)cs->ctl_cur_txn < cs->ctl_n_txns);
    struct raw_pkt_cmd *cur_req = &cs->ctl_txns[cs->ctl_cur_txn].req_pkt;
    struct raw_pkt_cmd req_copy;
    memcpy(&req_copy, cur_req, sizeof(req_copy));
    if (raw_pkt_hton(&req_copy) == 0) {
        bufferevent_write(cs->dbev, &req_copy, sizeof(req_copy));
    } else {
        log_ERR("ignoring attempt to send malformed request packet");
    }
    cs->wake_why &= ~CONTROL_WHY_DNODE_TXN;
}

static int dnode_data(struct control_session *cs, struct sockaddr *dnaddr)
{
    if (!cs->dpbuf.iov_base) {
        /* This can happen if e.g. the data node connection closes,
         * the client doesn't reconfigure us to stop streaming, and a
         * malicious actor sends something to the data port. */
        return -1;
    }
    struct sockaddr_storage sas;
    ssize_t s;
    while (1) {
        socklen_t sas_len = sizeof(sas);
        s = recvfrom(cs->ddatafd, cs->dpbuf.iov_base, cs->dpbuf.iov_len, 0,
                     (struct sockaddr*)&sas, &sas_len);
        if (s == -1) {
            switch (errno) {
#if EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:   /* fall through */
#endif
            case EAGAIN:
                log_WARNING("%s: spurious call; invoked with no data to read",
                            __func__);
                break;
            case EINTR:
                continue;
            }
            return -1;
        }
        break;
    }
    if ((size_t)s > cs->dpbuf.iov_len) {
        log_WARNING("truncated read getting sample from data node");
        return -1;
    }
    if (sas.ss_family != AF_INET && sas.ss_family != AF_INET6) {
        log_WARNING("unexpected remote address family %d", sas.ss_family);
        return -1;
    }
    if (!sockutil_addr_eq(dnaddr, (struct sockaddr*)&sas, 0)) {
        return -1;
    }
    return 0;
}

static const struct control_ops dnode_control_operations = {
    .cs_start = dnode_start,
    .cs_stop = dnode_stop,
    .cs_open = dnode_open,
    .cs_close = dnode_close,
    .cs_read = dnode_read,
    .cs_thread = dnode_thread,
    .cs_data = dnode_data,
};

const struct control_ops *control_dnode_ops = &dnode_control_operations;
