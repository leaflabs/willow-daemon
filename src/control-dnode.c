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

#include <stdlib.h>

#include "control-private.h"
#include "logging.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>

struct dnode_priv {
    struct evbuffer *d_rbuf;    /* Buffers control session ->req_pkt */
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

static void dnode_reset_priv(struct control_session *cs)
{
    struct dnode_priv *dpriv = cs->dpriv;
    control_must_lock(cs);
    evbuffer_drain(dpriv->d_rbuf, evbuffer_get_length(dpriv->d_rbuf));
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
    dnode_reset_priv(cs);
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
}

static int dnode_open(struct control_session *cs,
                      __unused evutil_socket_t control_sockfd)
{
    dnode_ensure_clean(cs);
    return 0;
}

static void dnode_close(struct control_session *cs)
{
    dnode_reset_priv(cs);
    dnode_ensure_clean(cs);
}

static int dnode_got_entire_res(struct control_session *cs)
{
    struct evbuffer *evb = bufferevent_get_input(cs->dbev);
    struct dnode_priv *dpriv = cs->dpriv;

    size_t d_rbuf_len = evbuffer_get_length(dpriv->d_rbuf);
    if (d_rbuf_len < sizeof(cs->res_pkt)) {
        evbuffer_remove_buffer(evb, dpriv->d_rbuf,
                               sizeof(cs->res_pkt) - d_rbuf_len);
    }

    int ret = evbuffer_get_length(dpriv->d_rbuf) == sizeof(cs->res_pkt);

    if (ret) {
        evbuffer_remove(dpriv->d_rbuf, &cs->res_pkt, sizeof(cs->res_pkt));
        if (raw_pkt_ntoh(&cs->res_pkt) == -1) {
            log_ERR("received malformed response packet from data node");
            ret = 0;
        }
    }
    return ret;
}

static enum control_worker_why
dnode_HACK_ensure_no_more_responses(struct control_session *cs,
                                    enum control_worker_why desired)
{
    /*
     * FIXME XXX: handle arrival of multiple asynchronous errors.
     *
     * This code is vulnerable to DoS attacks.
     *
     * We need a queue of responses, but that needs a maximum length
     * and useful response to it getting full (probably just sending a
     * reset signal and closing the connection), so we're robust
     * against a spray of error messages from a hosed data node.
     */
    if (dnode_got_entire_res(cs)) {
        log_CRIT("%s: oops, there were two dnode results on the wire, but "
                 "we only know how to handle one. we're toast :(",
                 __func__);
        return CONTROL_WHY_EXIT;
    }
    return desired;
}

static enum control_worker_why dnode_read(struct control_session *cs)
{
    /* If we've received an entire response packet, then convert it to
     * host byte ordering and get the worker thread to wake up and
     * invoke the client handler, which decides what to do with
     * it. Otherwise, leave the worker thread alone. */
    if (!dnode_got_entire_res(cs)) {
        return CONTROL_WHY_NONE;
    }
    log_DEBUG("%s: got response packet", __func__);
    return dnode_HACK_ensure_no_more_responses(cs, CONTROL_WHY_CLIENT_RES);
}

static void dnode_thread(struct control_session *cs)
{
    /* We should only wake up when the client handler has a request
     * for us to forward to the data node. */
    if (!(cs->wake_why & CONTROL_WHY_DNODE_REQ)) {
        log_ERR("dnode thread handler woke up unexpectedly");
        return;
    }
    log_DEBUG("%s: writing request packet", __func__);
    if (raw_pkt_hton(&cs->req_pkt) == 0) {
        bufferevent_write(cs->dbev, &cs->req_pkt, sizeof(struct raw_pkt_cmd));
    } else {
        log_ERR("ignoring attempt to send malformed request packet");
    }
    cs->wake_why &= ~CONTROL_WHY_DNODE_REQ;
}

static const struct control_ops dnode_control_operations = {
    .cs_start = dnode_start,
    .cs_stop = dnode_stop,
    .cs_open = dnode_open,
    .cs_close = dnode_close,
    .cs_read = dnode_read,
    .cs_thread = dnode_thread,
};

const struct control_ops *control_dnode_ops = &dnode_control_operations;
