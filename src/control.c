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

#include "control.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>

#include "logging.h"
#include "type_attrs.h"
#include "sockutil.h"
#include "control-private.h"
#include "control-client.h"
#include "control-dnode.h"

/* TODO use cached dnode_addr and dnode_c_port to establish periodic
 * reconnect handler to cover data node crashes. */

static void
control_fatal_err(const char *message, int code) /* code==-1 for "no code" */
{
    const char *msg = message ? message : "";
    const char *msgsep = message ? ": " : "";
    if (code > 0) {
        log_CRIT("fatal error (%d) in control session%s%s", code, msgsep, msg);
    } else {
        log_CRIT("fatal error in control session%s%s", msgsep, msg);
    }
    exit(EXIT_FAILURE);
}

/*
 * Client/dnode ops helpers
 */

static int control_client_start(struct control_session *cs)
{
    if (!control_client_ops->cs_start) {
        return 0;
    }
    return control_client_ops->cs_start(cs);
}

static void control_client_stop(struct control_session *cs)
{
    if (!control_client_ops->cs_stop) {
        return;
    }
    control_client_ops->cs_stop(cs);
}

static int control_client_open(struct control_session *cs,
                               evutil_socket_t sockfd)
{
    if (!control_client_ops->cs_open) {
        return 0;
    }
    return control_client_ops->cs_open(cs, sockfd);
}

static void control_client_close(struct control_session *cs)
{
    control_must_lock(cs);
    assert(cs->cbev);           /* or we never opened */
    bufferevent_free(cs->cbev);
    cs->cbev = NULL;
    if (cs->ctl_txns) {
        /* Hope you weren't in the middle of anything important... */
        log_DEBUG("client closing; clearing data node transactions");
        control_clear_transactions(cs, 1);
    }
    control_must_unlock(cs);
    if (control_client_ops->cs_close) {
        control_client_ops->cs_close(cs);
    }
}

static int control_client_read(struct control_session *cs)
{
    if (!control_client_ops->cs_read) {
        return CONTROL_WHY_NONE;
    }
    return control_client_ops->cs_read(cs);
}

static void control_client_thread(struct control_session *cs)
{
    if (!control_client_ops->cs_thread) {
        return;
    }
    control_client_ops->cs_thread(cs);
}

static int control_dnode_start(struct control_session *cs)
{
    if (!control_dnode_ops->cs_start) {
        return 0;
    }
    return control_dnode_ops->cs_start(cs);
}

static void control_dnode_stop(struct control_session *cs)
{
    if (!control_dnode_ops->cs_stop) {
        return;
    }
    control_dnode_ops->cs_stop(cs);
}

static int control_dnode_open(struct control_session *cs,
                              evutil_socket_t sockfd)
{
    if (!control_dnode_ops->cs_open) {
        return 0;
    }
    return control_dnode_ops->cs_open(cs, sockfd);
}

static void control_dnode_close(struct control_session *cs)
{
    control_must_lock(cs);
    assert(cs->dbev);           /* or we never opened */
    bufferevent_free(cs->dbev);
    cs->dbev = NULL;
    if (cs->ctl_txns) {
        /* FIXME if there are ongoing transactions, then the client
         * connection should also be open; we should get the
         * client-side code to send an error response (how?), or a
         * naive client will block forever. */
        log_INFO("halting data node I/O due to closed dnode connection");
        control_clear_transactions(cs, 1);
    }
    control_must_unlock(cs);
    if (control_dnode_ops->cs_close) {
        control_dnode_ops->cs_close(cs);
    }
}

static int control_dnode_read(struct control_session *cs)
{
    if (!control_dnode_ops->cs_read) {
        return CONTROL_WHY_NONE;
    }
    return control_dnode_ops->cs_read(cs);
}

static void control_dnode_thread(struct control_session *cs)
{
    if (!control_dnode_ops->cs_thread) {
        return;
    }
    control_dnode_ops->cs_thread(cs);
}

/*
 * Other helpers
 */

static struct evconnlistener*
control_new_listener(struct control_session *cs,
                     struct event_base *base, uint16_t port,
                     evconnlistener_cb cb, evconnlistener_errorcb err_cb)
{
    int sockfd = sockutil_get_tcp_passive(port, 1);
    if (sockfd == -1) {
        log_ERR("can't make socket: %m");
        return NULL;
    }
    evutil_make_socket_nonblocking(sockfd);
    unsigned flags = (LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE |
                      LEV_OPT_THREADSAFE);
    struct evconnlistener *ecl = evconnlistener_new(base, cb, cs,
                                                    flags, 0, sockfd);
    if (!ecl) {
        log_ERR("can't allocate evconnlistener");
        close(sockfd);
        return NULL;
    }
    evconnlistener_set_error_cb(ecl, err_cb);
    return ecl;
}

/* Returned bufferevent comes back disabled */
static struct bufferevent*
control_new_bev(struct control_session *cs, evutil_socket_t fd,
                bufferevent_data_cb readcb, bufferevent_data_cb writecb,
                bufferevent_event_cb eventcb)
{
    int bev_opts = BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE;
    struct bufferevent *ret = bufferevent_socket_new(control_get_base(cs),
                                                     fd, bev_opts);
    if (!ret) {
        return NULL;
    }
    bufferevent_disable(ret, bufferevent_get_enabled(ret));
    bufferevent_setcb(ret, readcb, writecb, eventcb, cs);
    return ret;
}

/* You don't have to use this if you've already got the lock */
static void control_set_wake(struct control_session *cs,
                             enum control_worker_why why)
{
    control_must_lock(cs);
    cs->wake_why |= why;
    control_must_unlock(cs);
}

/* You don't have to use this if you've got the lock */
static void control_must_wake(struct control_session *cs,
                              enum control_worker_why why)
{
    control_set_wake(cs, why);
    control_must_signal(cs);
}

/*
 * Worker thread
 */

static void* control_worker_main(void *csessvp)
{
    struct control_session *cs = csessvp;
    while (1) {
        control_must_lock(cs);
        while (cs->wake_why == CONTROL_WHY_NONE) {
            control_must_cond_wait(cs);
        }
        if (cs->wake_why & CONTROL_WHY_EXIT) {
            control_must_unlock(cs);
            pthread_exit(NULL);
        }
        if (cs->wake_why & (CONTROL_WHY_CLIENT_CMD |
                            CONTROL_WHY_CLIENT_RES |
                            CONTROL_WHY_CLIENT_ERR)) {
            control_client_thread(cs);
        }
        if (cs->wake_why & CONTROL_WHY_DNODE_TXN) {
            control_dnode_thread(cs);
        }
        control_must_unlock(cs);
    }
    control_fatal_err("control exiting unexpectedly", -1);
    return NULL; /* appease GCC */
}

/*
 * libevent plumbing
 */

static void control_bevt_handler(struct control_session *cs, short events,
                                 void (*on_close)(struct control_session*),
                                 const char *log_who)
{
    if (events & BEV_EVENT_EOF || events & BEV_EVENT_ERROR) {
        on_close(cs);
        log_INFO("%s connection closed", log_who);
    } else {
        log_WARNING("unhandled %s event; flags %d", log_who, events);
    }
}

static void control_client_event(__unused struct bufferevent *bev,
                                 short events, void *csessvp)
{
    struct control_session *cs = csessvp;
    assert(bev == cs->cbev);
    control_bevt_handler(cs, events, control_client_close, "client");
}

static void control_dnode_event(__unused struct bufferevent *bev,
                                short events, void *csessvp)
{
    /* FIXME install periodic event that tries to re-establish a
     * closed dnode connection */
    struct control_session *cs = csessvp;
    assert(bev == cs->dbev);
    control_bevt_handler(cs, events, control_dnode_close, "data node");
}

static void refuse_connection(evutil_socket_t fd,
                              const char *source, const char *cause)
{
    const char *c = cause ? cause : "unknown error";
    log_INFO("refusing new %s connection: %s", source, c);
    if (evutil_closesocket(fd)) {
        log_ERR("couldn't close new %s", source);
    }
}

static void
control_conn_open(struct control_session *cs,
                  struct bufferevent **bevp,
                  evutil_socket_t fd,
                  bufferevent_data_cb read,
                  bufferevent_data_cb write,
                  bufferevent_event_cb event,
                  int (*on_open)(struct control_session*,
                                 evutil_socket_t),
                  const char *log_who)
{
    if (*bevp) {
        refuse_connection(fd, log_who, "another is ongoing");
        return;
    }

    struct bufferevent *bev = control_new_bev(cs, fd, read, write, event);
    bufferevent_disable(bev, bufferevent_get_enabled(bev));
    if (!bev) {
        log_ERR("can't allocate resources for %s connection", log_who);
        return;
    }
    control_must_lock(cs);
    *bevp = bev;
    control_must_unlock(cs);
    if (on_open(cs, fd) == -1) {
        refuse_connection(fd, log_who, NULL);
        bufferevent_free(bev);
        *bevp = NULL;
    } else {
        bufferevent_enable(bev, EV_READ | EV_WRITE);
    }
    log_INFO("%s connection established", log_who);
}

static void
control_bev_reader(struct control_session *cs,
                   int (*reader)(struct control_session*),
                   void (*closer)(struct control_session*),
                   const char *log_who)
{
    int read_why_wake = reader(cs);
    switch (read_why_wake) {
    case -1:
        /*
         * TODO: add mechanism for sending an error first
         */
        log_INFO("forcibly closing %s connection", log_who);
        closer(cs);
        break;
    case CONTROL_WHY_NONE:
        break;
    case CONTROL_WHY_EXIT:
        log_CRIT("%s socket reader wants to shut down the worker", log_who);
        control_fatal_err("error while reading control socket", -1);
        break;
    default:
        control_must_wake(cs, (enum control_worker_why)read_why_wake);
        break;
    }
}

static void control_client_bev_read(__unused struct bufferevent *bev,
                                    void *csessvp)
{
    struct control_session *cs = csessvp;
    control_bev_reader(cs, control_client_read, control_client_close,
                       "client");
}

static void control_dnode_bev_read(__unused struct bufferevent *bev,
                                   void *csessvp)
{
    struct control_session *cs = csessvp;
    control_bev_reader(cs, control_dnode_read, control_dnode_close,
                       "data node");
}

static void client_ecl(__unused struct evconnlistener *ecl, evutil_socket_t fd,
                       __unused struct sockaddr *saddr, __unused int socklen,
                       void *csessvp)
{
    struct control_session *cs = csessvp;
    control_conn_open(cs, &cs->cbev, fd, control_client_bev_read, NULL,
                      control_client_event, control_client_open, "client");
}

static void client_ecl_err(__unused struct evconnlistener *ecl,
                           __unused void *csessvp)
{
    log_ERR("client accept() failed: %m");
}

/*
 * Public API
 */

static void control_init_cs(struct control_session *cs)
{
    cs->base = NULL;
    cs->cecl = NULL;
    cs->cbev = NULL;
    cs->cpriv = NULL;
    cs->daddr = NULL;
    cs->dport= 0;
    cs->dbev = NULL;
    cs->dpriv = NULL;
    cs->smpl = NULL;
    cs->wake_why = CONTROL_WHY_NONE;
    cs->ctl_txns = NULL;
    cs->ctl_n_txns = 0;
    cs->ctl_cur_txn = -1;
    cs->ctl_cur_rid = 0;
}

struct control_session* control_new(struct event_base *base,
                                    uint16_t client_port,
                                    const char* dnode_addr,
                                    uint16_t dnode_port,
                                    struct sample_session *smpl)
{
    int started_client = 0, started_dnode = 0;
    int mtx_en = 0, cv_en = 0, t_en = 0;
    struct control_session *cs = malloc(sizeof(struct control_session));
    if (!cs) {
        log_ERR("out of memory");
        return NULL;
    }
    control_init_cs(cs);

    cs->base = base;

    /* Set up locking */
    mtx_en = pthread_mutex_init(&cs->mtx, NULL);
    if (mtx_en) {
        log_ERR("threading error while initializing control session");
        goto bail;
    }
    cv_en = pthread_cond_init(&cs->cv, NULL);
    if (cv_en) {
        log_ERR("threading error while initializing control session");
        goto bail;
    }

    /* Client control fields */
    if (control_client_start(cs)) {
        log_ERR("can't start client side of control session");
        goto bail;
    }
    started_client = 1;
    cs->cecl = control_new_listener(cs, base, client_port, client_ecl,
                                    client_ecl_err);
    if (!cs->cecl) {
        log_ERR("can't listen for client connections");
        goto bail;
    }

    /* Data node control fields */
    if (control_dnode_start(cs)) {
        log_ERR("can't start data node side of control session");
        goto bail;
    }
    cs->daddr = dnode_addr;
    cs->dport = dnode_port;
    int dcontrolfd = sockutil_get_tcp_connected_p(cs->daddr, cs->dport);
    started_dnode = 1;
    if (dcontrolfd == -1) {
        log_ERR("can't connect to data node at %s, port %u",
                dnode_addr, dnode_port);
        goto bail;
    }
    if (evutil_make_socket_nonblocking(dcontrolfd)) {
        log_ERR("data node control socket doesn't support nonblocking I/O");
        goto bail;
    }
    control_conn_open(cs, &cs->dbev, dcontrolfd, control_dnode_bev_read,
                      NULL, control_dnode_event, control_dnode_open,
                      "data node");

    /* Sample session */
    cs->smpl = smpl;

    /* Start the worker thread */
    control_must_lock(cs);
    t_en = pthread_create(&cs->thread, NULL, control_worker_main, cs);
    control_must_unlock(cs);
    if (t_en) {
        log_ERR("can't start worker thread");
        goto bail;
    }

    return cs;

 bail:
    /* Tear down worker thread */
    if (t_en) {
        assert(0);              /* can't happen */
    }
    if (cv_en) {
        pthread_cond_destroy(&cs->cv);
    }
    if (mtx_en) {
        pthread_mutex_destroy(&cs->mtx);
    }

    /* Tear down data node control */
    if (started_dnode) {
        control_dnode_stop(cs);
    }
    if (cs->dbev) {
        bufferevent_free(cs->dbev);
    }

    /* Tear down client control */
    if (started_client) {
        control_client_stop(cs);
    }
    if (cs->cecl) {
        evconnlistener_free(cs->cecl);
    }
    if (cs->cbev) {
        bufferevent_free(cs->cbev);
    }

    return NULL;
}

void control_free(struct control_session *cs)
{
    /* NB: cs->cbev and cs->dbev had BEV_OPT_CLOSE_ON_FREE set on
     * creation, so there's no need to close the control sockets
     * here. */

    /* Acquired in control_new() */
    control_must_wake(cs, CONTROL_WHY_EXIT);
    control_must_join(cs, NULL);
    control_dnode_stop(cs);
    control_client_stop(cs);
    pthread_cond_destroy(&cs->cv);
    pthread_mutex_destroy(&cs->mtx);
    if (cs->dbev) {
        bufferevent_free(cs->dbev);
    }
    evconnlistener_free(cs->cecl);

    /* Possibly acquired elsewhere */
    if (cs->cbev) {
        bufferevent_free(cs->cbev);
    }
    if (cs->ctl_txns) {
        free(cs->ctl_txns);
    }

    free(cs);
}

struct event_base* control_get_base(struct control_session *cs)
{
    return cs->base;
}

/*
 * Private API
 */

void control_set_transactions(struct control_session *cs,
                              struct control_txn *txns, size_t n_txns,
                              int have_lock)
{
    if (!have_lock) {
        control_must_lock(cs);
    }
    /* You're not allowed to set up new transactions while existing
     * ones are ongoing, only to clear them. */
    assert((cs->ctl_txns == NULL &&
            cs->ctl_cur_txn == -1 &&
            cs->ctl_n_txns == 0) ||
           (txns == NULL && n_txns == 0));
    if (cs->ctl_txns) {
        free(cs->ctl_txns);
    }
    cs->ctl_txns = txns;
    cs->ctl_n_txns = n_txns;
    if (n_txns == 0) {
        cs->ctl_cur_txn = -1;
        goto done;
    }
    cs->ctl_cur_txn = 0;
    for (size_t i = 0; i < n_txns; i++) {
        ctxn_req(&txns[i])->r_id = cs->ctl_cur_rid++;
    }
 done:
    if (!have_lock) {
        control_must_unlock(cs);
    }
}

void __control_must_cond_wait(struct control_session *cs)
{
    int en = pthread_cond_wait(&cs->cv, &cs->mtx);
    if (en) {
        control_fatal_err("can't wait on next message", en);
    }
}

void __control_must_signal(struct control_session *cs)
{
    int en = pthread_cond_signal(&cs->cv);
    if (en) {
        control_fatal_err("can't signal cvar", en);
    }
}

void __control_must_lock(struct control_session *cs)
{
    int en = pthread_mutex_lock(&cs->mtx);
    if (en) {
        control_fatal_err("can't lock control thread", en);
    }
}

void __control_must_unlock(struct control_session *cs)
{
    int en = pthread_mutex_unlock(&cs->mtx);
    if (en) {
        control_fatal_err("can't unlock control thread", en);
    }
}

void __control_must_join(struct control_session *cs, void **retval)
{
    void *rv;
    if (!retval) {
        retval = &rv;
    }
    int en = pthread_join(cs->thread, retval);
    if (en) {
        control_fatal_err("can't join with control thread", en);
    }
}
