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

#include "raw_packets.h"
#include "proto/control.pb-c.h"

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
    CONTROL_WHY_CLIENT_ERR = 0x08, /* raw_pkt_cmd contianing an error
                                    * needs to be processed */

    /* These are processed by dnode-side code: */
    CONTROL_WHY_DNODE_TXN  = 0x10, /* Transaction must be performed */
};

/* Google says individual protocol buffers should be < 1 MB each:
 *
 * https://developers.google.com/protocol-buffers/docs/techniques#large-data
 *
 * So we might as well try to enforce reasonably good behavior. It's a
 * protocol error to send messages that are too long; client code is
 * and free to close such connections. */
#define CONTROL_CMD_MAX_SIZE (2 * 1024 * 1024)

/** Control session. */
struct control_session {
    /* control_new() caller owns this; we own the rest */
    struct event_base *base;

    /* Client */
    struct evconnlistener *cecl;
    struct bufferevent    *cbev;
    void *cpriv;

    /* Data node */
    const char         *daddr;
    uint16_t            dport;
    struct bufferevent *dbev;
    void               *dpriv;

    /* Board subsamples */
    unsigned ddataif; /* Daemon data socket interface number; see
                       * <net/if.h>.  Set during control_new(); treat
                       * as constant. */
    evutil_socket_t ddatafd; /* Daemon data socket, open entire session;
                              * main thread only */
    struct event *ddataevt;  /* Data socket event */
    struct sockaddr_storage dnaddr; /* Data node address; receive
                                     * sample data only from here. If
                                     * unset, .ss_family==AF_UNSPEC.
                                     * Shared with worker thread. */
    struct sockaddr_storage caddr; /* Client address; forward live
                                    * sample data to here. If unset,
                                    * .ss_family==AF_UNSPEC. Shared
                                    * with worker thread. */
    struct iovec dpbuf; /* Data socket protocol buffer; main thread
                         * only. */

    /* Worker thread */
    pthread_t thread;
    pthread_cond_t cv; /* Wakes up ->thread */
    pthread_mutex_t mtx; /* For ->cv and other main thread critical sections */
    unsigned wake_why; /* OR of control_worker_why flags describing
                        * why ->thread needs to wake up */

    /* Command processing -- use control_set_transactions() to set up work */
    struct control_txn *ctl_txns; /* Transactions to perform as part
                                   * of processing a client command,
                                   * or NULL if not working on one. */
    size_t ctl_n_txns;          /* Length of ctl_txns */
    ssize_t ctl_cur_txn;        /* Current transaction, or -1 if not
                                 * performing one. */
    uint16_t ctl_cur_rid;       /* Current raw packet request ID; wraps. */
};

/**
 * Subclass hooks.
 *
 * Subclasses should provide these; others should never touch them.
 */
struct control_ops {
    /* Session-wide startup and teardown callbacks. These may be NULL
     * if you don't have anything special to do.
     *
     * The start callback is invoked from control_new() before the
     * worker thread is created. The stop callback is invoked from
     * more places, but never while the worker thread is running. */
    int (*cs_start)(struct control_session *cs);
    void (*cs_stop)(struct control_session *cs);

    /* Per-connection open/close callbacks; use these e.g. to allocate
     * any per-connection state. These may be NULL also.
     *
     * When the open callback is invoked, the corresponding
     * bufferevent is valid, but disabled. When both open and close are
     * called, the control_session lock is not held.
     *
     * Returning -1 from the open callback will refuse the
     * connection. The close callback is invoked from a libevent
     * handler, so there's nowhere to pass errors up to. */
    int (*cs_open)(struct control_session *cs, evutil_socket_t control_sockfd);
    void (*cs_close)(struct control_session *cs);

    /* On-receive control socket callback.
     *
     * Pull data out of your bufferevent. If that's not enough data,
     * return CONTROL_WHY_NONE. If you've got something to wake up the
     * worker with, return an appropriate control_worker_why code. */
    enum control_worker_why (*cs_read)(struct control_session *cs);

    /* Worker thread callback. */
    void (*cs_thread)(struct control_session *cs);

    /* Data socket callbacks.
     *
     * Return 0 on success, -1 on failure. */
    int (*cs_data)(struct control_session *cs, struct sockaddr *saddr);
};

/*
 * Threading helpers
 */

#define CONTROL_DEBUG_LOG 0 /* more verbose logging (helps with pthreads) */

#if CONTROL_DEBUG_LOG
#define CONTROL_DEBUG log_DEBUG
#else
#define CONTROL_DEBUG(...) ((void)0)
#endif

#ifndef CONTROL_DEBUG
#define control_must_cond_wait __control_must_cond_wait
#define control_must_signal __control_must_signal
#define control_must_lock __control_must_lock
#define control_must_unlock __control_must_unlock
#define control_must_join __control_must_join
#else
#define control_must_cond_wait(cs) do {                 \
        CONTROL_DEBUG("%s: cond_wait", __func__);         \
        __control_must_cond_wait(cs); } while (0)
#define control_must_signal(cs) do {                            \
        __control_must_signal(cs);                              \
        CONTROL_DEBUG("%s: signalled", __func__); } while (0)
#define control_must_lock(cs) do {                              \
        CONTROL_DEBUG("%s: locking", __func__);                   \
        __control_must_lock(cs);                                \
        CONTROL_DEBUG("%s: locked", __func__);  } while (0)
#define control_must_unlock(cs) do {                            \
        CONTROL_DEBUG("%s: unlocking", __func__);                 \
        __control_must_unlock(cs);                              \
        CONTROL_DEBUG("%s: unlocked", __func__); } while (0)
#define control_must_join(cs, rv) do {               \
        CONTROL_DEBUG("%s: join", __func__);           \
        __control_must_join(cs, rv); } while (0)
#endif

void __control_must_cond_wait(struct control_session *cs);
void __control_must_signal(struct control_session *cs);
void __control_must_lock(struct control_session *cs);
void __control_must_unlock(struct control_session *cs);
void __control_must_join(struct control_session *cs, void **retval);

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

#endif
