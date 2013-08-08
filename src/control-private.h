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

/**
 * @file src/control-private.h
 *
 * For control session internal use only
 */

#ifndef _SRC_CONTROL_PRIVATE_H_
#define _SRC_CONTROL_PRIVATE_H_

#include <event2/util.h>
#include <pthread.h>
#include <sys/socket.h>
#include <stdint.h>

#include "client_socket.h"
#include "raw_packets.h"
#include "safe_pthread.h"
#include "proto/control.pb-c.h"

#include "sample.h"

struct event;
struct event_base;
struct evconnlistener;
struct bufferevent;

/* For decoding protocol messages into requests/responses. Contains a
 * single req/res transaction that needs to take place. */
struct control_txn {
    struct raw_pkt_cmd req_pkt;        /* Request to perform */
    struct raw_pkt_cmd res_pkt;        /* Holds received response */
};

/* Get the request out of a transaction */
static inline struct raw_cmd_req* ctxn_req(struct control_txn *txn)
{
    return raw_req(&txn->req_pkt);
}

/* Get the response out of a transaction */
static inline struct raw_cmd_res* ctxn_res(struct control_txn *txn)
{
    return raw_res(&txn->res_pkt);
}

/* Flags for why we woke up the worker thread */
enum control_worker_why {
    CONTROL_WHY_NONE   = 0x00, /* Go back to sleep (e.g. spurious wakeup) */

    CONTROL_WHY_EXIT   = 0x01, /* Thread should exit */

    /* These are processed by client-side code: */
    CONTROL_WHY_CLIENT_CMD = 0x02, /* Unpacked new client command message */
    CONTROL_WHY_CLIENT_RES = 0x04, /* raw_pkt_cmd containing a response
                                    * needs to be processed */
    CONTROL_WHY_CLIENT_ERR = 0x08, /* raw_pkt_cmd containing an error
                                    * needs to be processed */

    /* These are processed by dnode-side code: */
    CONTROL_WHY_DNODE_TXN  = 0x10, /* Transaction must be performed */
};

/* Flags for why we woke up the dnode connector thread */
enum control_dnode_conn_why {
    CONTROL_DCONN_WHY_NONE = 0x0, /* Go back to sleep */
    CONTROL_DCONN_WHY_CONN = 0x2, /* Connection is required */
};

/** Control session. */
struct control_session {
    /* Lock ordering: mtx, then dnode_conn_mtx. */

    /* control_new() caller owns this; we own the rest */
    struct event_base *base;

    /* Client control */
    struct evconnlistener *cecl;
    struct bufferevent    *cbev;
    void *cpriv;

    /* Data node control */
    const char         *daddr;  /* Treat as constant */
    uint16_t            dport;  /* Treat as constant */
    struct bufferevent *dbev;   /* Event loop thread,
                                 * worker thread,
                                 * dnode_conn_t.
                                 *
                                 * Protected by worker mutex. */
    evutil_socket_t     dcontrolfd; /* Main thread and dnode_conn_t. */
    struct event       *dconn_evt; /* Activated by dnode_conn_t. */
    void               *dpriv;  /* control-dnode.c only */

    /* Data node sample handling */
    struct sample_session *smpl;

    /* Worker thread */
    pthread_t thread;
    pthread_cond_t cv; /* Wakes up ->thread */
    pthread_mutex_t mtx; /* For ->cv and other main thread critical sections */
    unsigned wake_why; /* OR of control_worker_why flags describing
                        * why ->thread needs to wake up */

    /* Data node reconnection thread
     *
     * This is a workaround for bugs in libevent's asynchronous connection
     * launching code, as implemented by bufferevent_socket_connect() in
     * libevent 2.0.16-stable-1, as distributed with Ubuntu 12.04.
     *
     * In that version, when the connection you're trying to make fails
     * (e.g. if the data node is down), then the bufferevent will hit your
     * callback twice in quick succession, once to let you know that there
     * was an error, and then again with a "success" argument.
     *
     * Rather than add a brittle "quirks mode" that ignores the
     * success callback, we just do blocking connect() in another
     * thread, which uses event_active() to notify the main thread
     * when the data node connection is available.
     */
    pthread_t dnode_conn_t;
    unsigned dnode_conn_why;
    pthread_cond_t dnode_conn_cv; /* The thread pthread_cond_wait()s
                                   * on this after the connection has
                                   * been made. The main thread will
                                   * signal it when the dnode
                                   * connection has been lost. */
    pthread_mutex_t dnode_conn_mtx; /* For dnode_conn_cv. */

    /* Command processing -- use control_set_transactions() to set up work */
    struct control_txn *ctl_txns; /* Transactions to perform as part
                                   * of processing a client command,
                                   * or NULL if not working on one. */
    size_t ctl_n_txns;          /* Length of ctl_txns */
    ssize_t ctl_cur_txn;        /* Current transaction, or -1 if not
                                 * performing one. */
    uint16_t ctl_cur_rid;       /* Current raw packet request ID; wraps. */

    /* Transaction timeout
     *
     * We protect against a hosed data node with this. */
    struct event *txn_timeout_evt; /* Data node transaction timed out */
};

/**
 * Client/data node hooks.
 *
 * Client and data node files provide these for use by the top-level
 * control socket handlers; others should never touch them.
 */
struct control_ops {
    /* Session-wide startup and teardown callbacks. These may be NULL.
     *
     * The start callback is invoked from control_new(), before the
     * worker thread is created, with the worker thread lock held. The
     * stop callback is invoked from more places, but never while the
     * worker thread is running. */
    int (*cs_start)(struct control_session *cs);
    void (*cs_stop)(struct control_session *cs);

    /* Per-connection open/close callbacks; use these e.g. to allocate
     * any per-connection state. These may be NULL also.
     *
     * Open is called WITH the control_session lock held.
     * Close is called WITHOUT the control_session lock held.
     *
     * When the open callback is invoked, the corresponding
     * bufferevent is valid, but disabled.
     *
     * Returning -1 from the open callback will close the
     * connection. The close callback is invoked from a libevent
     * handler, so there's nowhere to pass errors up to. */
    int (*cs_open)(struct control_session *cs, evutil_socket_t control_sockfd);
    void (*cs_close)(struct control_session *cs);

    /* On-receive control socket callback.
     *
     * This is called WITHOUT the control_session lock held.
     *
     * Pull data out of your bufferevent. If that's not enough data,
     * return CONTROL_WHY_NONE. If you've got something to wake up the
     * worker with, return another appropriate control_worker_why
     * code. If something went wrong and the connection needs closing,
     * return -1. */
    int (*cs_read)(struct control_session *cs);

    /* Callback for when the other side of the connection closed.
     *
     * E.g., if the client socket closes, then the data node's
     * cs_partner_closed() gets called, and vice-versa.
     *
     * This function is called with the control_session mutex held.
     */
    void (*cs_partner_closed)(struct control_session *cs);

    /* Worker thread callback.
     *
     * This is called with the control_session mutex held. */
    void (*cs_thread)(struct control_session *cs);
};

/*
 * Threading helpers for the main control session mutex
 */

static inline void control_must_cond_wait(struct control_session *cs)
{
    safe_p_cond_wait(&cs->cv, &cs->mtx);
}

static inline void control_must_signal(struct control_session *cs)
{
    safe_p_cond_signal(&cs->cv);
}

static inline void control_must_lock(struct control_session *cs)
{
    safe_p_mutex_lock(&cs->mtx);
}

static inline void control_must_unlock(struct control_session *cs)
{
    safe_p_mutex_unlock(&cs->mtx);
}

static inline void control_must_join(struct control_session *cs,
                                     void **retval)
{
    safe_p_join(cs->thread, retval);
}

/*
 * Deferred work helpers
 */

/* Sets up data node transactions to be performed as deferred work.
 *
 * Doesn't start the deferred work; you'll need to do that from a read
 * callback's return value.
 *
 * have_lock: set to 0 if you already have the control session mutex
 *            locked, 1 otherwise.
 */
void control_set_transactions(struct control_session *cs,
                              struct control_txn *txns, size_t n_txns,
                              int have_lock);

/* Clear any pending transactions. */
static inline void control_clear_transactions(struct control_session *cs,
                                              int have_lock)
{
    if (!have_lock) {
        control_must_lock(cs);
    }
    control_set_transactions(cs, NULL, 0, 1);
    cs->wake_why &= ~(CONTROL_WHY_DNODE_TXN | CONTROL_WHY_CLIENT_RES);
    if (!have_lock) {
        control_must_unlock(cs);
    }
}

/*
 * Transaction timeout
 */

/* NOT SYNCHRONIZED */
static inline int control_is_txn_timeout_pending(struct control_session *cs)
{
    return cs->txn_timeout_evt != NULL;
}

/**
 * Start a new transaction timeout.
 *
 * NOT SYNCHRONIZED, cs->mtx must be held.
 *
 * Start the timeout when a transaction begins, after you've sent the
 * request. If the timeout expires, the data node is assumed to be
 * hosed, and its connection will be forcibly closed. You must thus
 * clear the timeout when the transaction is complete.
 *
 * @param cs Control session.
 * @return
 */
int control_start_txn_timeout(struct control_session *cs);

/**
 * Clear any ongoing transaction timeout.
 *
 * NOT SYNCHRONIZED, cs->mtx must be held.
 *
 * @param cs Control session.
 */
void control_clear_txn_timeout(struct control_session *cs);

#endif
