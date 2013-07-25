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
#include <sys/time.h>
#include <sys/types.h>

#include <event2/event.h>
#include <event2/util.h>

#include "ch_storage.h"
#include "logging.h"
#include "raw_packets.h"
#include "safe_pthread.h"
#include "sockutil.h"
#include "type_attrs.h"
#include "proto/control.pb-c.h"
#include "proto/data.pb-c.h"

static void sample_ddatafd_callback(evutil_socket_t, short, void*);
static void sample_timeout_callback(evutil_socket_t, short, void*);
#define SAMPLE_THREAD_DONE EV_READ /* hack? */
#define SAMPLE_THREAD_ERR  EV_WRITE
#define SAMPLE_THREAD_SLEEPING EV_TIMEOUT
static void sample_worker_callback(evutil_socket_t, short, void*);

union sample_packet {
    struct raw_pkt_bsub bsub;
    struct raw_pkt_bsmp bsmp;
};

/* Flags for why the worker thread woke up */
enum sample_worker_why {
    SAMPLE_WHY_NONE = 0x00,     /* No reason; go back to sleep */
    SAMPLE_WHY_EXIT = 0x01,     /* Thread should exit */
    SAMPLE_WHY_STOP = 0x02,     /* Main thread has halted transfer;
                                 * please wake it up to ACK that
                                 * you're done and are going to
                                 * sleep. */
    SAMPLE_WHY_BSAMPS = 0x04,   /* Board samples waiting to be written */
};

/* Reasons why we're stopping board sample storage */
enum sample_stop_why {
    SAMPLE_STOP_NONE = 0,
    SAMPLE_STOP_TIMEOUT,
    SAMPLE_STOP_PKTDROP,
    SAMPLE_STOP_NET_ERR,
    SAMPLE_STOP_PKT_ERR,
};

#define SAMPLE_PBUF_ARR_SIZE (1024 * 1024)
#define SAMPLE_BSAMP_KHZ 30 /* sample frequency; TODO: don't hard-code here */
#define SAMPLE_BSAMP_SEC_P_BUF 2 /* seconds of data per sample buffer */
#define SAMPLE_BSAMP_MAXLEN (SAMPLE_BSAMP_KHZ * 1000 * SAMPLE_BSAMP_SEC_P_BUF)
#define SAMPLE_BSAMP_TIMEOUT_SEC 3 /* WISHLIST: be smarter */
#define SAMPLE_BSAMP_TIMEOUT_USEC 0
struct sample_session {
    /*
     * Lock ordering: smpl_mtx, then worker_mtx, then bsamp_mtx.
     *
     * WISHLIST simplify the locking, probably by having the worker
     * flip the sample buffers instead of the packet receive handlers
     * (unlike the packet receivers, which can't block the event loop,
     * the worker is free to sleep while grabbing the double-buffer
     * write lock).
     */

    struct event_base *base;
    unsigned ddataif; /* Daemon data socket interface number; see
                       * <net/if.h>.  Set during control_new().
                       *
                       * Treat as constant. */
    evutil_socket_t ddatafd; /* Daemon data socket, open entire session.
                              *
                              * Event loop thread only. */
    struct iovec dpktbuf; /* Points to raw packet buffer for ddatafd.
                           * Event loop thread only. */

    /* Buffers for initializing and packing data protocol
     * messages. Event loop thread only. */
    uint32_t c_bsub_chips[RAW_BSUB_NSAMP];
    uint32_t c_bsub_chans[RAW_BSUB_NSAMP];
    uint32_t c_bsub_samps[RAW_BSUB_NSAMP];
    uint8_t *c_sample_pbuf_arr;

    /* Data socket event. Event loop thread only. */
    struct event *ddataevt;

    /*
     * This group of fields is shared with worker threads (as in
     * plural, i.e., NOT JUST THE SAMPLE WORKER THREAD), and are
     * protected by smpl_mtx.
     */
    pthread_mutex_t smpl_mtx;
    struct sockaddr_storage dnaddr; /* Data node address; receive
                                     * [sub]samples from here only. If
                                     * unset, .ss_family==AF_UNSPEC. */
    struct sockaddr_storage caddr; /* Client address; forward
                                    * subsamples to here. If unset,
                                    * .ss_family==AF_UNSPEC. */
    int forward_subs;  /* If true, we forward subsamples from data
                        * node to client. */
    sample_bsamp_cb smpl_cb; /**<
                               * Callback function for sample
                               * retrieval and storage. */
    void *smpl_cb_arg;       /**< Passed to smpl_cb. */
    /**
     * For detecting timeouts during board sample reception. */
    struct event *smpl_timeout_evt;
    /**
     * Worker activates this so we can notify the caller of
     * sample_expect_bsamps() when things have happened.*/
    struct event *smpl_worker_evt;
    size_t smpl_next_sidx;      /**< Next board sample index */
    enum sample_stop_why smpl_stop_why; /**< Why are we stopping storage? */

    /*
     * Worker thread
     *
     * These are shared between the sample reader thread and
     * ->worker's.
     */
    pthread_mutex_t        worker_mtx; /**< Protects this group of fields */
    pthread_t              worker;     /**< Worker thread */
    pthread_cond_t         worker_cv;  /**< Worker waits on this */
    enum sample_worker_why worker_why; /**< Why worker_cv was signaled */
    /**
     * worker_using_buf[i] == 0 initially, and subsequently == 1 iff
     * there's data in bsamp_bufs[i] that the worker has yet to finish
     * writing to disk.
     *
     * Reader thread (i.e. event loop thread) sets these to 1, worker
     * thread clears them when it's done.
     */
    int worker_using_buf[2];
    /**
     * Number of samples worker has written during this sample storage
     * operation, or 0. */
    size_t worker_nwritten;

    /*
     * Board sample double-buffering
     *
     * This group of fields is shared between the worker and reader
     * threads. (The reader grabs samples off the network in ->base's
     * event loop thread).
     *
     * The worker takes a read lock when it's storing
     * bsamp_bufs[bsamp_widx] to disk. It never writes to any of these
     * fields.
     *
     * The reader thread has exclusive ownership over the non-worker
     * buffer and its length. It tries to take a write lock when it's
     * time to flip buffers. Failure to do so means samples get lost.
     */
    pthread_rwlock_t bsamp_mtx;
    struct raw_pkt_bsmp *bsamp_bufs[2]; /**< Buffer expected board samples. */
    size_t bsamp_buflen[2];  /**< Number of samples in each bsamp_bufs. */
    size_t bsamp_widx;       /**< Worker index into bsamp_bufs/bsamp_buflen. */
    /** Cached sample storage configuration. */
    struct sample_bsamp_cfg bsamp_cfg;

    /*
     * Debugging; event loop thread only.
     */
    uint32_t debug_last_sub_idx;
    int debug_print_ddatafd;    /* debug printing in ddatafd callback */
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

static inline void sample_must_join(struct sample_session *smpl)
{
    safe_p_join(smpl->worker, NULL);
}

static inline void sample_must_lock(struct sample_session *smpl)
{
    safe_p_mutex_lock(&smpl->smpl_mtx);
}

static inline void sample_must_unlock(struct sample_session *smpl)
{
    safe_p_mutex_unlock(&smpl->smpl_mtx);
}

static inline void sample_must_lock_worker(struct sample_session *smpl)
{
    safe_p_mutex_lock(&smpl->worker_mtx);
}

static inline void sample_must_unlock_worker(struct sample_session *smpl)
{
    safe_p_mutex_unlock(&smpl->worker_mtx);
}

static inline void sample_must_cond_wait_worker(struct sample_session *smpl)
{
    safe_p_cond_wait(&smpl->worker_cv, &smpl->worker_mtx);
}

static inline void sample_must_signal_worker(struct sample_session *smpl)
{
    safe_p_cond_signal(&smpl->worker_cv);
}

static inline void sample_must_rdlock_dbuf(struct sample_session *smpl)
{
    safe_p_rwlock_rdlock(&smpl->bsamp_mtx);
}

static inline void sample_must_wrlock_dbuf(struct sample_session *smpl)
{
    safe_p_rwlock_wrlock(&smpl->bsamp_mtx);
}

static inline int sample_must_trywrlock_dbuf(struct sample_session *smpl)
{
    return safe_p_rwlock_trywrlock(&smpl->bsamp_mtx);
}

static inline void sample_must_rwunlock_dbuf(struct sample_session *smpl)
{
    safe_p_rwlock_unlock(&smpl->bsamp_mtx);
}

/*
 * Worker thread
 */

static void* sample_worker_main(void *smplvp)
{
    struct sample_session *smpl = smplvp;
    while (1) {
        sample_must_lock_worker(smpl);
        while (smpl->worker_why == SAMPLE_WHY_NONE) {
            sample_must_cond_wait_worker(smpl);
        }
        if (smpl->worker_why & SAMPLE_WHY_EXIT) {
            /* Reader thread wants us to quit. */
            smpl->worker_why &= ~SAMPLE_WHY_EXIT;
            sample_must_unlock_worker(smpl);
            pthread_exit(NULL);
        }
        if (smpl->worker_why & SAMPLE_WHY_BSAMPS) {
            int write_err = 0;

            /* Reader thread has a buffer of samples waiting for us to
             * store. */
            smpl->worker_why &= ~SAMPLE_WHY_BSAMPS;
            sample_must_unlock_worker(smpl);

            /* Try to store the samples. */
            sample_must_rdlock_dbuf(smpl);
            size_t i = smpl->bsamp_widx;
            size_t len = smpl->bsamp_buflen[i];
            if (len) {
                write_err = ch_storage_write(smpl->bsamp_cfg.chns,
                                             smpl->bsamp_bufs[i], len);
            }
            sample_must_rwunlock_dbuf(smpl);

            /* Set the state which tells the reader thread we're not
             * using the buffer anymore. */
            sample_must_lock_worker(smpl);
            smpl->worker_using_buf[i] = 0;
            if (!write_err) {
                smpl->worker_nwritten += len;
                log_DEBUG("%s: stored %zu new board samples, total %zu",
                          __func__, len, smpl->worker_nwritten);
            } else {
                log_DEBUG("%s: ERROR storing packets: %m", __func__);
            }
            sample_must_unlock_worker(smpl);

            /* Wake up the reader thread and let it know what happened. */
            short what = write_err ? SAMPLE_THREAD_ERR : SAMPLE_THREAD_DONE;
            if (what == SAMPLE_THREAD_ERR) {
                /*
                 * FIXME this won't hit the main thread right away,
                 * and in the meantime, it might ask us to write some
                 * more stuff. Maybe add a "worker's ignoring you now
                 * KTHXBYE" flag we can protect with worker_mtx?
                 */
                log_DEBUG("%s: notifying main thread about write error",
                          __func__);
            }
            sample_must_lock(smpl);
            event_active(smpl->smpl_worker_evt, what, 0);
            sample_must_unlock(smpl);

            /* Re-grab the worker lock (which we released so we could
             * block in ch_storage_write(), above) for the next
             * conditional. */
            sample_must_lock_worker(smpl);
        }
        if (smpl->worker_why & SAMPLE_WHY_STOP) {
            /* Reader thread wants us to know that this transfer has
             * ended for some reason. Let it know know we heard it and
             * go back to sleep. */
            smpl->worker_why &= ~SAMPLE_WHY_STOP;
            sample_must_unlock_worker(smpl);
            sample_must_lock(smpl);
            event_active(smpl->smpl_worker_evt, SAMPLE_THREAD_SLEEPING, 0);
            sample_must_unlock(smpl);
            continue;
        }
        sample_must_unlock_worker(smpl);
    }
    sample_fatal_err("sample worker exiting unexpectedly", -1);
    return NULL;
}

/*
 * Other helpers
 */

static const char* sample_stop_why_str(enum sample_stop_why why)
{
    switch (why) {
    case SAMPLE_STOP_NONE: return "no reason";
    case SAMPLE_STOP_TIMEOUT: return "timeout while waiting for packet";
    case SAMPLE_STOP_PKTDROP: return "dropped packet";
    case SAMPLE_STOP_NET_ERR: return "network error";
    case SAMPLE_STOP_PKT_ERR: return "packet with error flag set";
    }
    assert(0);                  /* placate GCC */
    return "";
}

/* NOT SYNCHRONIZED (smpl_mtx) */
static inline int sample_expecting_bsamps(struct sample_session *smpl)
{
    return (smpl->smpl_timeout_evt != NULL &&
            smpl->smpl_stop_why == SAMPLE_STOP_NONE);
}

/* NOT SYNCHRONIZED (smpl_mtx) */
static inline int sample_expecting_bsubs(struct sample_session *smpl)
{
    return (smpl->forward_subs &&
            smpl->dnaddr.ss_family != AF_UNSPEC &&
            smpl->caddr.ss_family != AF_UNSPEC);
}

/* NOT SYNCHRONIZED (wr bsamp_mtx) */
static void sample_init_bsamp_cfg(struct sample_session *smpl)
{
    smpl->bsamp_cfg.nsamples = 0;
    smpl->bsamp_cfg.start_sample = 0;
    smpl->bsamp_cfg.chns = NULL;
}

/*
 * Release non-timeout resources acquired while expecting board samples.
 *
 * IMPORTANT: this takes the write lock on the sample buffer, so DO
 * NOT CALL THIS FUNCTION FROM THE EVENT LOOP THREAD unless the worker
 * is sleeping, or you'll block the event loop if the worker is
 * writing samples.
 */
/* ACQUIRES worker_mtx, ACQUIRES (wr) bsamp_mtx */
static void sample_finished_with_bsamps(struct sample_session *smpl)
{
    sample_must_wrlock_dbuf(smpl);
    assert(smpl->bsamp_bufs[0] && smpl->bsamp_bufs[1]);
    free(smpl->bsamp_bufs[0]);
    free(smpl->bsamp_bufs[1]);
    smpl->bsamp_bufs[0] = NULL;
    smpl->bsamp_bufs[1] = NULL;
    smpl->bsamp_buflen[0] = 0;
    smpl->bsamp_buflen[1] = 0;
    smpl->bsamp_widx = 0;
    sample_init_bsamp_cfg(smpl);
    sample_must_rwunlock_dbuf(smpl);

    sample_must_lock_worker(smpl);
    smpl->worker_using_buf[0] = 0;
    smpl->worker_using_buf[1] = 0;
    smpl->worker_why &= ~SAMPLE_WHY_BSAMPS;
    sample_must_unlock_worker(smpl);
}

/* NOT SYNCHRONIZED (smpl_mtx) */
static int sample_reset_timeout(struct sample_session *smpl)
{
    struct timeval timeout = {
        .tv_sec = SAMPLE_BSAMP_TIMEOUT_SEC,
        .tv_usec = SAMPLE_BSAMP_TIMEOUT_USEC,
    };
    assert(smpl->smpl_timeout_evt);
    return evtimer_add(smpl->smpl_timeout_evt, &timeout);
}

/* NOT SYNCHRONIZED (smpl_mtx) */
static void sample_clear_timeout(struct sample_session *smpl)
{
    if (smpl->smpl_timeout_evt) {
        event_free(smpl->smpl_timeout_evt);
        smpl->smpl_timeout_evt = NULL;
    }
}

/*
 * Clear (delete) the board sample timeout, and release any other
 * resources acquired while expecting board samples.
 *
 * SEE IMPORTANT COMMENTS ABOVE sample_finished_with_bsamps()
 */
/* NOT SYNCHRONIZED (smpl_mtx), CALLS sample_finished_with_bsamps() */
static void __sample_reject_bsamps_internal(struct sample_session *smpl)
{
    assert(sample_expecting_bsamps(smpl));

    assert(smpl->smpl_timeout_evt);
    sample_clear_timeout(smpl);

    sample_finished_with_bsamps(smpl);
}

/*
 * SEE IMPORTANT COMMENTS ABOVE sample_finished_with_bsamps()
 */
#define sample_reject_bsamps_internal(smpl) do {                        \
        log_DEBUG("%s: rejecting further board samples", __func__);     \
        __sample_reject_bsamps_internal(smpl);                          \
    } while (0)

/* Timeout or dropped packet occurred while reading board samples. Get
 * the worker thread to acknowledge and go back to sleep.
 *
 * NOT SYNCHRONIZED (smpl_mtx), ACQUIRES worker_mtx, (wr) bsamp_mtx */
static void sample_stop_worker(struct sample_session *smpl,
                               enum sample_stop_why why)
{
    log_ERR("halting sample storage due to %s", sample_stop_why_str(why));
    smpl->smpl_stop_why = why;
    sample_must_lock_worker(smpl);
    smpl->worker_why |= SAMPLE_WHY_STOP;
    sample_must_unlock_worker(smpl);
    sample_must_signal_worker(smpl);
}

static int sample_init_pthreads(struct sample_session *smpl)
{
    int ret = -1;
    int smpl_destroy = 0;
    int work_destroy = 0;
    int dbuf_destroy = 0;
    int cv_destroy = 0;
    int t_destroy = 0;

    smpl_destroy = !pthread_mutex_init(&smpl->smpl_mtx, NULL);
    if (!smpl_destroy) {
        goto out;
    }
    work_destroy = !pthread_mutex_init(&smpl->worker_mtx, NULL);
    if (!work_destroy) {
        goto out;
    }
    cv_destroy = !pthread_cond_init(&smpl->worker_cv, NULL);
    if (!cv_destroy) {
        goto out;
    }
    dbuf_destroy = !pthread_rwlock_init(&smpl->bsamp_mtx, NULL);
    if (!dbuf_destroy) {
        goto out;
    }
    t_destroy = !pthread_create(&smpl->worker, NULL, sample_worker_main,
                                smpl);
    if (!t_destroy) {
        goto out;
    }
    ret = 0;
 out:
    if (ret) {
        if (smpl_destroy) {
            pthread_mutex_destroy(&smpl->smpl_mtx);
        }
        if (work_destroy) {
            pthread_mutex_destroy(&smpl->worker_mtx);
        }
        if (cv_destroy) {
            pthread_cond_destroy(&smpl->worker_cv);
        }
        if (dbuf_destroy) {
            pthread_rwlock_destroy(&smpl->bsamp_mtx);
        }
        /* No need to clean up smpl->worker; we did that last, so
         * either it hasn't been created or creation failed. */
        assert(!t_destroy);
    }
    return ret;
}

/* NOT SYNCHRONIZED */
static void sample_init(struct sample_session *smpl)
{
    smpl->base = NULL;
    smpl->ddataif = 0;
    smpl->ddatafd = -1;
    smpl->dpktbuf.iov_base = NULL;
    smpl->dpktbuf.iov_len = 0;
    smpl->c_sample_pbuf_arr = NULL;
    smpl->ddataevt = NULL;
    smpl->dnaddr.ss_family = AF_UNSPEC;
    smpl->caddr.ss_family = AF_UNSPEC;
    smpl->forward_subs = 0;
    smpl->smpl_cb = NULL;
    smpl->smpl_cb_arg = NULL;
    smpl->smpl_timeout_evt = NULL;
    smpl->smpl_worker_evt = NULL;
    smpl->smpl_next_sidx = 0;
    smpl->smpl_stop_why = SAMPLE_STOP_NONE;
    smpl->worker_why = SAMPLE_WHY_NONE;
    smpl->worker_using_buf[0] = 0;
    smpl->worker_using_buf[1] = 0;
    smpl->worker_nwritten = 0;
    smpl->bsamp_bufs[0] = NULL;
    smpl->bsamp_bufs[1] = NULL;
    smpl->bsamp_buflen[0] = 0;
    smpl->bsamp_buflen[1] = 0;
    smpl->bsamp_widx = 0;
    sample_init_bsamp_cfg(smpl);
    smpl->debug_last_sub_idx = 0;
    smpl->debug_print_ddatafd = 1;
}

/*
 * Public API
 */

struct sample_session *sample_new(struct event_base *base,
                                  unsigned iface,
                                  uint16_t port)
{
    /* Allocate/init the sample_session and initialize pthreads before doing
     * anything else. */
    struct sample_session *smpl = malloc(sizeof(struct sample_session));
    if (!smpl) {
        return NULL;
    }
    sample_init(smpl);
    if (sample_init_pthreads(smpl) == -1) {
        log_ERR("%s: threading error during initialization", __func__);
        free(smpl);
        return NULL;
    }

    /* Bring up the sample_session. */
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
    smpl->smpl_worker_evt = event_new(smpl->base, -1,
                                      (SAMPLE_THREAD_DONE |
                                       SAMPLE_THREAD_ERR |
                                       SAMPLE_THREAD_SLEEPING |
                                       EV_PERSIST),
                                      sample_worker_callback, smpl);
    if (!smpl->smpl_worker_evt ||
        event_add(smpl->smpl_worker_evt, NULL) == -1) {
        log_ERR("%s: can't configure thread callback", __func__);
        goto fail;
    }
    return smpl;

 fail:
    sample_free(smpl);
    return NULL;
}

void sample_free(struct sample_session *smpl)
{
    /* Bring down the worker thread first. */
    sample_must_lock_worker(smpl);
    smpl->worker_why |= SAMPLE_WHY_EXIT;
    sample_must_unlock_worker(smpl);
    sample_must_signal_worker(smpl);
    sample_must_join(smpl);

    /* Next, clean up any stray samples we're waiting for. */
    sample_must_lock(smpl);
    if (sample_expecting_bsamps(smpl)) {
        log_WARNING("halting sample storage prematurely");
        sample_reject_bsamps_internal(smpl);
    }
    assert(!sample_expecting_bsamps(smpl));
    sample_must_unlock(smpl);
    if (smpl->ddataevt) {
        event_free(smpl->ddataevt);
    }
    free(smpl->c_sample_pbuf_arr);
    free(smpl->dpktbuf.iov_base);
    if (smpl->ddatafd != -1 && evutil_closesocket(smpl->ddatafd)) {
        log_ERR("can't close data socket");
    }
    pthread_mutex_destroy(&smpl->smpl_mtx);
    pthread_mutex_destroy(&smpl->worker_mtx);
    pthread_cond_destroy(&smpl->worker_cv);
    pthread_rwlock_destroy(&smpl->bsamp_mtx);
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

/* NOT SYNCHRONIZED (smpl_mtx) */
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
 out:
    sample_must_unlock(smpl);
    return ret;
}

/* NOT SYNCHRONIZED (smpl_mtx) */
static int sample_enable_subsamples(struct sample_session *smpl)
{
    if (smpl->dnaddr.ss_family == AF_UNSPEC ||
        smpl->caddr.ss_family == AF_UNSPEC) {
        return -1;
    }
    smpl->forward_subs = 1;
    return 0;
}

/* NOT SYNCHRONIZED (smpl_mtx) */
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

/* ACQUIRES (worker_mtx) */
static void sample_setup_bsamp_worker(struct sample_session *smpl)
{
    sample_must_lock_worker(smpl);
    assert(!(smpl->worker_why & (SAMPLE_WHY_STOP | SAMPLE_WHY_BSAMPS)));
    assert(smpl->worker_using_buf[0] == 0 && smpl->worker_using_buf[1] == 0);
    smpl->worker_using_buf[0] = 0;
    smpl->worker_using_buf[1] = 0;
    smpl->worker_nwritten = 0;
    sample_must_unlock_worker(smpl);
}

/* ACQUIRES (wr bsamp_mtx) */
static int sample_setup_dbuf(struct sample_session *smpl,
                             struct sample_bsamp_cfg *cfg)
{
    const size_t bufsize = SAMPLE_BSAMP_MAXLEN * sizeof(struct raw_pkt_bsmp);
    int ret = 0;
    if (sample_must_trywrlock_dbuf(smpl) == EBUSY) {
        log_ERR("%s: not expecting samples, but can't wrlock sample buffers",
                __func__);
        return -1;
    }
    assert(!smpl->bsamp_bufs[0] && !smpl->bsamp_bufs[1]);
    smpl->bsamp_buflen[0] = 0;
    smpl->bsamp_buflen[1] = 0;
    smpl->bsamp_widx = 0;
    smpl->bsamp_bufs[0] = malloc(bufsize);
    smpl->bsamp_bufs[1] = malloc(bufsize);
    if (!smpl->bsamp_bufs[0] || !smpl->bsamp_bufs[1]) {
        log_ERR("%s: out of memory", __func__);
        free(smpl->bsamp_bufs[0]);
        free(smpl->bsamp_bufs[1]);
        smpl->bsamp_bufs[0] = NULL;
        smpl->bsamp_bufs[1] = NULL;
        sample_init_bsamp_cfg(smpl);
        ret = -1;
        goto out;
    }
    memcpy(&smpl->bsamp_cfg, cfg, sizeof(smpl->bsamp_cfg));
 out:
    sample_must_rwunlock_dbuf(smpl);
    return ret;
}

/* NOT SYNCHRONIZED (smpl_mtx) */
static int sample_setup_bsamp_events(struct sample_session *smpl)
{
    assert(!smpl->smpl_timeout_evt);
    smpl->smpl_timeout_evt = evtimer_new(smpl->base, sample_timeout_callback,
                                         smpl);
    if (!smpl->smpl_timeout_evt) {
        log_ERR("%s: can't create timeout event", __func__);
        goto fail;
    }
    if (sample_reset_timeout(smpl) == -1) {
        log_ERR("%s: can't configure data timeout", __func__);
        goto fail;
    }
    return 0;

 fail:
    sample_clear_timeout(smpl);
    return -1;
}

int sample_expect_bsamps(struct sample_session *smpl,
                         struct sample_bsamp_cfg *cfg,
                         sample_bsamp_cb cb, void *arg)
{
    int ret = -1;
    if (cb == NULL) {
        log_ERR("%s: received NULL callback argument", __func__);
        assert(0);
        return -1;
    }

    log_DEBUG("expecting %zu board samples, start index %zd",
              cfg->nsamples, cfg->start_sample);

    sample_must_lock(smpl);
    assert(!sample_expecting_bsamps(smpl));
    if (smpl->dnaddr.ss_family == AF_UNSPEC) {
        log_ERR("can't expect board samples with missing data node address");
        goto out;
    }

    /* Set up worker */
    sample_setup_bsamp_worker(smpl);

    /* Set up sample double-buffering */
    if (sample_setup_dbuf(smpl, cfg)) {
        goto out;
    }

    /* Set up timeout and thread notifier events */
    if (sample_setup_bsamp_events(smpl)) {
        goto out;
    }

    /* Grab the callback and cache the start index, and done. */
    assert(!smpl->smpl_cb && !smpl->smpl_cb_arg);
    smpl->smpl_cb = cb;
    smpl->smpl_cb_arg = arg;
    smpl->smpl_next_sidx = (size_t)cfg->start_sample;
    ret = 0;
 out:
    sample_must_unlock(smpl);
    return ret;
}

ssize_t sample_reject_bsamps(struct sample_session *smpl)
{
    ssize_t ret;
    sample_must_lock(smpl);
    sample_reject_bsamps_internal(smpl);
    sample_must_unlock(smpl);
    sample_must_lock_worker(smpl);
    ret = smpl->worker_nwritten;
    sample_must_unlock_worker(smpl);
    return ret;
}

/*
 * libevent sample retrieval callbacks
 */

/* This function gets called when the timeout occurs. It passes that
 * information along to the worker, which finishes flushing what it
 * has and stops. The worker must notice and activate
 * sample_worker_callback()'s event when it's done. */
static void sample_timeout_callback(__unused evutil_socket_t ignored,
                                    short events, void *smplvp)
{
    struct sample_session *smpl = smplvp;
    assert(events & EV_TIMEOUT);
    if (events != EV_TIMEOUT) {
        log_WARNING("%s: ignoring additional events:%s%s", __func__,
                    (events & EV_READ ? " EV_READ" : ""),
                    (events & EV_WRITE ? " EV_WRITE" : ""));
        return;
    }
    /* Stop the transfer and get the worker to acknowledge it's time
     * to stop. */
    sample_stop_worker(smpl, SAMPLE_STOP_TIMEOUT);
}

/* The worker uses this to let the reader know about things that
 * happen, and to acknowledge when the main thread needs it to go to
 * sleep.
 *
 * We only ever invoke the sample_session's smpl_cb from here, as it
 * needs to know how many samples were written, and this is the only
 * place where we can rely on no more samples being written. */
static void sample_worker_callback(__unused evutil_socket_t ignored,
                                   short what, void *smplvp)
{
    struct sample_session *smpl = smplvp;
    short cb_flags = 0;

    /*
     * Decide what to do about whatever happened to the worker.
     */
    if (what & SAMPLE_THREAD_DONE) {
        /* Worker finished storing its buffer; mark it unused. */
        sample_must_lock_worker(smpl);
        sample_must_rdlock_dbuf(smpl);
        smpl->worker_using_buf[smpl->bsamp_widx] = 0;
        if (smpl->worker_nwritten == smpl->bsamp_cfg.nsamples) {
            cb_flags |= SAMPLE_BS_DONE;
        }
        sample_must_rwunlock_dbuf(smpl);
        sample_must_unlock_worker(smpl);
    }
    if (what & SAMPLE_THREAD_SLEEPING) {
        /* Worker acknowledges halt and has gone to sleep. */
        sample_must_lock(smpl);
        switch (smpl->smpl_stop_why) {
        case SAMPLE_STOP_NONE:
            log_WARNING("spurious sample worker callback");
            break;
        case SAMPLE_STOP_TIMEOUT:
            cb_flags |= SAMPLE_BS_TIMEOUT;
            break;
        case SAMPLE_STOP_NET_ERR:
            cb_flags |= SAMPLE_BS_ERR;
            break;
        case SAMPLE_STOP_PKTDROP:
            cb_flags |= SAMPLE_BS_PKTDROP;
            break;
        case SAMPLE_STOP_PKT_ERR:
            cb_flags |= SAMPLE_BS_ERR;
            break;
        default:
            log_WARNING("sample worker sleeping for unknown reason");
            break;
        }
        smpl->smpl_stop_why = SAMPLE_STOP_NONE;
        sample_must_unlock(smpl);
    }

    /* If there's no reason to invoke the callback, then we're done. */
    if (!cb_flags) {
        return;
    }

    /* NOTE: when control flow reaches this point, the worker should
     * be sleeping. We'll still grab the locks in case of bugs. */
    sample_must_lock_worker(smpl);
    size_t nwritten = smpl->worker_nwritten;
    sample_must_unlock_worker(smpl);
    sample_must_rdlock_dbuf(smpl);
    assert(!(cb_flags & SAMPLE_BS_DONE) ||
           (nwritten == smpl->bsamp_cfg.nsamples));
    sample_must_rwunlock_dbuf(smpl);

    sample_must_lock(smpl);
    if (sample_expecting_bsamps(smpl)) {
        /* If we're still expecting samples, we need to clear the
         * timeout as well as reject further ones. */
        sample_reject_bsamps_internal(smpl);
    } else {
        /* This happens instead at normal end of operations, when all
         * the samples have been read. */
        sample_finished_with_bsamps(smpl);
    }
    assert(smpl->smpl_cb);
    smpl->smpl_cb(cb_flags, nwritten, smpl->smpl_cb_arg);
    smpl->smpl_cb = NULL;
    smpl->smpl_cb_arg = NULL;
    sample_must_unlock(smpl);
}

/*
 * libevent data socket handling
 */

/* NOT SYNCHRONIZED (rd bsamp_mtx) */
static inline size_t sample_last_sidx(struct sample_session *smpl)
{
    struct sample_bsamp_cfg *bcfg = &smpl->bsamp_cfg;
    assert(bcfg->start_sample >= 0);
    return (size_t)bcfg->start_sample + bcfg->nsamples - 1;
}

/* NOT SYNCHRONIZED (smpl_mtx, rd bsamp_mtx) */
static inline size_t sample_samps_left(struct sample_session *smpl)
{
    struct sample_bsamp_cfg *bcfg = &smpl->bsamp_cfg;
    if (bcfg->start_sample >= 0) {
        return (size_t)bcfg->start_sample + bcfg->nsamples -
            smpl->smpl_next_sidx;
    } else {
        return bcfg->nsamples;
    }
}

/* Read new samples into the free buffer.
 * NOT SYNCHRONIZED (smpl_mtx) */
#define GOT_BSAMPS 0
#define FILLED_BUFFER 1
#define GOT_LAST_BSAMP 2
#define DROPPED_PKT (-1)
#define SOCKET_ERR (-2)
#define GOT_NOTHING (-3)
#define GOT_PKT_ERR (-4)
static int sample_ddatafd_grab_bsamps(struct sample_session *smpl)
{
    struct sockaddr_storage sas;
    socklen_t sas_len = sizeof(sas);
    int ret = GOT_NOTHING;

    sample_must_rdlock_dbuf(smpl);
    size_t myidx = 0x1 ^ smpl->bsamp_widx;
    struct raw_pkt_bsmp *mybufs = smpl->bsamp_bufs[myidx];
    const size_t s_left = sample_samps_left(smpl);
    const size_t b_start = smpl->bsamp_buflen[myidx];
    const size_t b_avail = SAMPLE_BSAMP_MAXLEN - b_start;
    const size_t b_end = b_start + (b_avail > s_left ? s_left : b_avail);
    const size_t max_bad_packets = 20;

    size_t i = b_start;
    size_t n_bad = 0; /* number of bad packets since last good packet. */
    while (i < b_end) {
        if (n_bad > max_bad_packets) {
            log_WARNING("%s: too many bad packets; returning early", __func__);
            break;
        }

        ssize_t s = recvfrom(smpl->ddatafd, &mybufs[i],
                             sizeof(struct raw_pkt_bsmp), 0,
                             (struct sockaddr*)&sas, &sas_len);
        if (s == -1) {
            switch (errno) {
#if EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:   /* fall through */
#endif
            case EAGAIN:
                goto done;
            case EINTR:
                continue;
            default:
                log_WARNING("%s: recvfrom: %m", __func__);
                ret = SOCKET_ERR;
                goto done;
            }
        }

        /*
         * Check the packet.
         */
        if (!sockutil_addr_eq((struct sockaddr*)&smpl->dnaddr,
                              (struct sockaddr*)&sas, 0)) {
            log_DEBUG("ignoring data socket packet from unexpected address");
            n_bad++;
            continue;
        }
        /* Make sure the packet is a well-formed board sample. */
        if (raw_pkt_ntoh(&mybufs[i])) {
            log_WARNING("dropping malformed data packet");
            n_bad++;
            continue;
        }
        uint8_t mtype = raw_mtype(&mybufs[i]);
        if (mtype != RAW_MTYPE_BSMP) {
            log_DEBUG("ignoring data packet with wrong mtype %s",
                      raw_mtype_str(mtype));
            n_bad++;
            continue;
        }
        if (raw_pkt_is_err(&mybufs[i])) {
            log_INFO("board sample %u has error flag set", mybufs[i].b_sidx);
            ret = GOT_PKT_ERR;
            break;
        }
        /* If this is the first packet, and we don't care about
         * indexes, then start counting from here. */
        if (smpl->bsamp_cfg.start_sample == -1) {
            smpl->bsamp_cfg.start_sample = mybufs[i].b_sidx;
            smpl->smpl_next_sidx = mybufs[i].b_sidx;
        }
        /* Check for dropped or reordered packets. */
        if (mybufs[i].b_sidx != smpl->smpl_next_sidx++) {
            log_DEBUG("%s: dropped packet; expected index %zu, got %u",
                      __func__, smpl->smpl_next_sidx - 1, mybufs[i].b_sidx);
            ret = DROPPED_PKT;
            break;
        }

        /*
         * Packet retrieved successfully!
         */
        i++;
        n_bad = 0;
    }
 done:
    /* Check if we actually got any board samples. */
    if (i > b_start && ret != GOT_PKT_ERR) {
        ret = GOT_BSAMPS;
    }
    /* If we did, update the buffer length, and see if it's time to flip
     * the buffer, or if we're done altogether. */
    if (ret == GOT_BSAMPS) {
        smpl->bsamp_buflen[myidx] = i;
        if (smpl->smpl_next_sidx > sample_last_sidx(smpl)) {
            ret = GOT_LAST_BSAMP;
        } else if (smpl->bsamp_buflen[myidx] == SAMPLE_BSAMP_MAXLEN) {
            ret = FILLED_BUFFER;
        }
    }
    sample_must_rwunlock_dbuf(smpl);
    return ret;
}

static void sample_flip_bsamp_bufs(struct sample_session *smpl)
{
    /* Try to swap buffers with the worker thread. */
    sample_must_lock_worker(smpl);
    if (smpl->worker_using_buf[smpl->bsamp_widx]) {
        log_DEBUG("%s: worker's using the other buffer; dropping packets",
                  __func__);
        sample_must_unlock_worker(smpl);
        sample_stop_worker(smpl, SAMPLE_STOP_PKTDROP);
        return;
    }
    if (sample_must_trywrlock_dbuf(smpl) == EBUSY) {
        log_DEBUG("%s: can't write-lock buffer; dropping packets",
                  __func__);
        sample_must_unlock_worker(smpl);
        sample_stop_worker(smpl, SAMPLE_STOP_PKTDROP);
        return;
    }
    smpl->bsamp_buflen[smpl->bsamp_widx] = 0;
    smpl->bsamp_widx ^= 1;
    smpl->worker_using_buf[smpl->bsamp_widx] = 1;
    smpl->worker_why |= SAMPLE_WHY_BSAMPS;
    sample_must_rwunlock_dbuf(smpl);
    sample_must_unlock_worker(smpl);
    sample_must_signal_worker(smpl);
    return;
}

/* NOT SYNCHRONIZED (smpl_mtx) */
static void sample_ddatafd_bsamps(struct sample_session *smpl)
{
    switch (sample_ddatafd_grab_bsamps(smpl)) {
    case GOT_BSAMPS:
        /* Samples are safely buffered; we're done. */
        sample_reset_timeout(smpl);
        return;
    case FILLED_BUFFER:
        /* Read buffer is full; get the worker to store the samples. */
        sample_reset_timeout(smpl);
        sample_flip_bsamp_bufs(smpl);
        return;
    case GOT_LAST_BSAMP:
        /* That's the last one; time to stop. */
        sample_clear_timeout(smpl);
        sample_flip_bsamp_bufs(smpl);
        return;
    case DROPPED_PKT:
        sample_stop_worker(smpl, SAMPLE_STOP_PKTDROP);
        return;
    case SOCKET_ERR:
        sample_stop_worker(smpl, SAMPLE_STOP_NET_ERR);
        return;
    case GOT_NOTHING:
        /* Only incorrect or malformed packets were on the wire. */
        return;
    case GOT_PKT_ERR:
        sample_stop_worker(smpl, SAMPLE_STOP_PKT_ERR);
        return;
    }
}

/* NOT SYNCHRONIZED */
static int sample_get_bsub_packet(struct sample_session *smpl,
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
    if (raw_pkt_ntoh(iov->iov_base)) {
        log_INFO("dropping malformed data node packet");
        return -1;
    }
    uint8_t mtype = raw_mtype(iov->iov_base);
    if (mtype != RAW_MTYPE_BSUB) {
        log_DEBUG("unexpected message type %s (%u) received on data socket",
                  raw_mtype_str(mtype), mtype);
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
    msg_bsub->has_is_err = 1;
    msg_bsub->is_err = !!raw_pkt_is_err(bsub);
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
    struct raw_pkt_bsub *bsub = (struct raw_pkt_bsub*)smpl->dpktbuf.iov_base;
    BoardSubsample msg_bsub = BOARD_SUBSAMPLE__INIT;
    msg_bsub.chips = smpl->c_bsub_chips;
    msg_bsub.channels = smpl->c_bsub_chans;
    msg_bsub.samples = smpl->c_bsub_samps;
    DnodeSample dnsample = DNODE_SAMPLE__INIT;
    sample_init_pmsg_from_bsub(&msg_bsub, bsub);
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

/* NOT SYNCHRONIZED */
static void sample_ddatafd_bsubs(struct sample_session *smpl)
{
    struct sockaddr *dnaddr = (struct sockaddr*)&smpl->dnaddr;
    struct sockaddr *caddr = (struct sockaddr*)&smpl->caddr;
    /* Fill the data node sample packet buffer. */
    if (sample_get_bsub_packet(smpl, dnaddr)) {
        log_DEBUG("%s: can't get data packet from data node", __func__);
        recv(smpl->ddatafd, NULL, 0, 0);
        return;
    }
    /* Convert the raw packet to protobuf and ship that to the client. */
    if (sample_convert_and_ship_subsample(smpl, caddr)) {
        log_DEBUG("%s: can't forward data node subsample to client", __func__);
    }
}

static void sample_ddatafd_empty_recv_queue(struct sample_session *smpl)
{
    do {
        switch (recv(smpl->ddatafd, NULL, 0, 0)) {
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:       /* fall through */
#endif
        case EAGAIN:            /* fall through */
        case EINTR:
            continue;
        default:
            return;
        }
    } while (1);
}

static void sample_ddatafd_callback(evutil_socket_t ddatafd, short events,
                                    void *smplvp)
{
    struct sample_session *smpl = smplvp;
    assert(smpl->ddatafd == ddatafd);
    assert(events & EV_READ);

    sample_must_lock(smpl);
    if (sample_expecting_bsamps(smpl)) {
        sample_ddatafd_bsamps(smpl);
        smpl->debug_print_ddatafd = 1;
    } else if (sample_expecting_bsubs(smpl)) {
        sample_ddatafd_bsubs(smpl);
        smpl->debug_print_ddatafd = 1;
    } else {
        if (smpl->debug_print_ddatafd) {
            log_DEBUG("ignoring unwanted activity on data socket");
            smpl->debug_print_ddatafd = 0;
        }
        sample_ddatafd_empty_recv_queue(smpl);
    }
    sample_must_unlock(smpl);
}

