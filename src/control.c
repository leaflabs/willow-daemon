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
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>             /* for sig_atomic_t */

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
    if (!control_client_ops->cs_close) {
        return;
    }
    control_client_ops->cs_close(cs);
}

static enum control_worker_why control_client_read(struct control_session *cs)
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
    if (!control_dnode_ops->cs_close) {
        return;
    }
    return control_dnode_ops->cs_close(cs);
}

static enum control_worker_why control_dnode_read(struct control_session *cs)
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
        assert(cs->wake_why != CONTROL_WHY_NONE);
        if (cs->wake_why & CONTROL_WHY_EXIT) {
            control_must_unlock(cs);
            pthread_exit(NULL);
        }
        if (cs->wake_why & (CONTROL_WHY_CLIENT_CMD | CONTROL_WHY_CLIENT_RES)) {
            control_client_thread(cs);
        }
        if (cs->wake_why & CONTROL_WHY_DNODE_REQ) {
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
                                 struct bufferevent **bevp,
                                 void (*on_close)(struct control_session*),
                                 const char *log_who)
{
    if (events & BEV_EVENT_EOF || events & BEV_EVENT_ERROR) {
        control_must_lock(cs);
        bufferevent_free(*bevp);
        *bevp = NULL;
        control_must_unlock(cs);
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
    control_bevt_handler(cs, events, &cs->cbev, control_client_close,
                         "client");
    assert(cs->cbev == NULL);
}

static void control_dnode_event(__unused struct bufferevent *bev,
                                short events, void *csessvp)
{
    struct control_session *cs = csessvp;
    assert(bev == cs->dbev);
    control_bevt_handler(cs, events, &cs->dbev, control_dnode_close,
                         "data node");
    assert(cs->dbev == NULL);
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
control_ecl_handler(struct control_session *cs,
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
                   enum control_worker_why (*reader)(struct control_session*))
{
    enum control_worker_why read_why_wake = reader(cs);
    switch (read_why_wake) {
    case CONTROL_WHY_NONE:
        break;
    case CONTROL_WHY_EXIT:
        control_fatal_err("client processor signaled error", -1);
        break;
    default:
        control_must_wake(cs, read_why_wake);
        break;
    }
}

static void control_client_bev_read(__unused struct bufferevent *bev,
                                    void *csessvp)
{
    struct control_session *cs = csessvp;
    control_bev_reader(cs, control_client_read);
}

static void control_dnode_bev_read(__unused struct bufferevent *bev,
                                   void *csessvp)
{
    struct control_session *cs = csessvp;
    control_bev_reader(cs, control_dnode_read);
}

static void client_ecl(__unused struct evconnlistener *ecl, evutil_socket_t fd,
                       __unused struct sockaddr *saddr, __unused int socklen,
                       void *csessvp)
{
    struct control_session *cs = csessvp;
    control_ecl_handler(cs, &cs->cbev, fd, control_client_bev_read, NULL,
                        control_client_event, control_client_open, "client");
}

static void dnode_ecl(__unused struct evconnlistener *ecl, evutil_socket_t fd,
                      __unused struct sockaddr *saddr, __unused int socklen,
                      void *csessvp)
{
    struct control_session *cs = csessvp;
    control_ecl_handler(cs, &cs->dbev, fd, control_dnode_bev_read, NULL,
                        control_dnode_event, control_dnode_open, "data node");
}

static void client_ecl_err(__unused struct evconnlistener *ecl,
                           __unused void *csessvp)
{
    log_ERR("client accept() failed: %m");
}

static void dnode_ecl_err(__unused struct evconnlistener *ecl,
                          __unused void *csessvp)
{
    log_ERR("data node accept() failed: %m");
}

/*
 * Public API
 */

struct control_session* control_new(struct event_base *base,
                                    uint16_t cport, uint16_t dport)
{
    int en;
    struct control_session *cs = malloc(sizeof(struct control_session));
    if (!cs) {
        goto nocs;
    }
    struct evconnlistener *cecl =
        control_new_listener(cs, base, cport, client_ecl, client_ecl_err);
    if (!cecl) {
        goto nocecl;
    }
    struct evconnlistener *decl =
        control_new_listener(cs, base, dport, dnode_ecl, dnode_ecl_err);
    if (!decl) {
        goto nodecl;
    }
    en = pthread_mutex_init(&cs->mtx, NULL);
    if (en) {
        goto nomtx;
    }
    en = pthread_cond_init(&cs->cv, NULL);
    if (en) {
        goto nocv;
    }
    control_must_lock(cs);
    cs->wake_why = CONTROL_WHY_NONE;
    control_must_unlock(cs);
    cs->base = base;
    cs->cecl = cecl;
    cs->decl = decl;
    cs->cbev = NULL;
    cs->dbev = NULL;
    if (control_client_start(cs)) {
        goto noclient;
    }
    if (control_dnode_start(cs)) {
        goto nodnode;
    }
    control_must_lock(cs);
    en = pthread_create(&cs->thread, NULL, control_worker_main, cs);
    control_must_unlock(cs);
    if (en) {
        goto noworker;
    }
    return cs;

 noworker:
    control_dnode_stop(cs);
 nodnode:
    control_client_stop(cs);
 noclient:
    en = pthread_cond_destroy(&cs->cv);
    if (en) {
        control_fatal_err("can't destroy cvar", en);
    }
 nocv:
    en = pthread_mutex_destroy(&cs->mtx);
    if (en) {
        control_fatal_err("can't destroy cs mutex", en);
    }
 nomtx:
    evconnlistener_free(decl);
 nodecl:
    evconnlistener_free(cecl);
 nocecl:
    free(cs);
 nocs:
    return NULL;
}

void control_free(struct control_session *cs)
{
    /* Acquired in control_new() */
    control_must_wake(cs, CONTROL_WHY_EXIT);
    control_must_join(cs, NULL);
    control_dnode_stop(cs);
    control_client_stop(cs);
    pthread_cond_destroy(&cs->cv);
    pthread_mutex_destroy(&cs->mtx);
    evconnlistener_free(cs->decl);
    evconnlistener_free(cs->cecl);
    /* Possibly acquired by evconnlistener callbacks */
    if (cs->dbev) {
        bufferevent_free(cs->dbev);
    }
    if (cs->cbev) {
        bufferevent_free(cs->cbev);
    }
    free(cs);
}

struct event_base* control_get_base(struct control_session *cs)
{
    return cs->base;
}

/*
 * pthreads helpers
 */

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
