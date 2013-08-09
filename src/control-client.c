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

#include <fcntl.h> /* leave this here; our __unused conflicts with it */

#include "control-client.h"
#include "control-private.h"

#include <stdlib.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "type_attrs.h"
#include "logging.h"
#include "raw_packets.h"
#include "sockutil.h"
#include "ch_storage.h"
#include "hdf5_ch_storage.h"
#include "raw_ch_storage.h"

#include "sample.h"

#define LOCAL_DEBUG_LOGV 0

#if LOCAL_DEBUG_LOGV
#define LOCAL_DEBUG(...) log_DEBUG(__VA_ARGS__)
#else
#define LOCAL_DEBUG(...) ((void)0)
#endif

#define HDF5_DATASET_NAME "wired-dataset"
#define DEFAULT_STORAGE_BACKEND STORAGE_BACKEND__STORE_HDF5

/* Workaround for FPGA issues. == 30 * 1120. */
#define DAQ_MAGIC_MODULUS 1920
#define DAQ_MAGIC_MODULUS_STR "1920"

/* If we restart a sample storage request at the same index this many
 * times, then we've failed to actually write anything to disk over
 * too many attempts, and will send an error response to the
 * client. */
#define MAX_FAILED_STORAGE_RETRIES 5

struct client_priv {
    ControlCommand *c_cmd; /* Latest unpacked protocol message, or
                            * NULL. Shared with worker thread. */
    ControlResponse *c_rsp;     /* Latest response to send, or NULL.
                                 * Worker thread only. */

    struct evbuffer *c_pbuf; /* buffers c_cmd's protocol buffer until
                              * all c_pbuflen bytes of it are received. */
    struct evbuffer *c_pbuflen_buf; /* buffers c_pbuflen until all
                                     * sizeof(client_cmd_len_t)
                                     * bytes are received. */
    client_cmd_len_t c_pbuflen;     /* length of c_pbuf, which client
                                     * sends before c_pbuf */

    /* Allocate a command and response's worth of contiguous space at
     * client_start() time, rather than using e.g. evbuffer_pullup()
     * at each read(). */
    uint8_t c_cmd_arr[CLIENT_CMD_MAX_SIZE];
    uint8_t c_rsp_arr[CLIENT_CMD_MAX_SIZE];

    /* For storing addresses we read from the data node over the
     * course of a command */
    struct sockaddr_in dn_addr_in;

    /* For configuring sample storage */
    struct sample_bsamp_cfg *bs_cfg;
    int bs_expecting;        /* Are we currently expecting samples? */
    ssize_t bs_restart_pending;  /* If we're not pending a restart,
                                  * this is -1.
                                  *
                                  * Otherwise, it's the number of
                                  * samples written during the last
                                  * time we wanted to restart a sample
                                  * storage operation, but had to wait
                                  * for the transactions from the
                                  * previous one to complete. */
    struct event *bs_response_pend_evt; /* For the background thread to
                                        * let main thread know it's
                                        * safe to actually do a
                                        * restart that couldn't go
                                        * forward previously. */
    short bs_pending_events; /* The short events we're pending on */
    int bs_restarted;        /* Are we handling a restarted storage of
                              * canned board samples?
                              *
                              * If not, this equals zero. If so, it's
                              * the number of times we've restarted
                              * since the last time we actually wrote
                              * anything to disk. */
    size_t bs_nwritten_cache; /* Cached number of written samples,
                               * for handling restarts. */
};

/********************************************************************
 * Miscellaneous helpers
 */

static inline struct client_priv* cpriv(struct control_session *cs)
{
    return (struct client_priv*)cs->cpriv;
}

/* NOT SYNCHRONIZED */
static inline int client_is_response_pending(struct control_session *cs)
{
    return cpriv(cs)->bs_response_pend_evt != NULL;
}

/* NOT SYNCHRONIZED */
static void client_unpend_restart(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    cpriv->bs_restart_pending = -1;
    if (cpriv->bs_response_pend_evt) {
        event_free(cpriv->bs_response_pend_evt);
        cpriv->bs_response_pend_evt = NULL;
    }
}

/* NOT SYNCHRONIZED
 *
 * If a transfer is ongoing, rejects further samples and halts the
 * transfer.
 *
 * This can take a while if the worker is running, so try not to call
 * it from the event loop thread.
 */
static void client_halt_ongoing_transfer(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    if (cpriv->bs_expecting) {
        log_DEBUG("prematurely rejecting board samples; this may block");
        assert(cpriv->bs_cfg);
        sample_reject_bsamps(cs->smpl);
        ch_storage_close(cpriv->bs_cfg->chns);
        ch_storage_free(cpriv->bs_cfg->chns);
        free(cpriv->bs_cfg);
        cpriv->bs_cfg = NULL;
        client_unpend_restart(cs);
    }
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
    if (cpriv->c_pbuflen_buf) {
        evbuffer_free(cpriv->c_pbuflen_buf);
    }
    client_halt_ongoing_transfer(cs);
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
    cpriv->c_pbuflen = CLIENT_CMDLEN_WAITING;
    if (cpriv->c_rsp) {
        control_response__free_unpacked(cpriv->c_rsp, NULL);
    }
    cpriv->c_rsp = NULL;
    if (cpriv->bs_cfg) {
        free(cpriv->bs_cfg);
    }
    cpriv->bs_cfg = NULL;
    cpriv->bs_expecting = 0;
    cpriv->bs_restarted = 0;
    cpriv->bs_pending_events = 0;
    client_unpend_restart(cs);
    cpriv->bs_nwritten_cache = 0;
    drain_evbuf(cpriv->c_pbuf);
    drain_evbuf(cpriv->c_pbuflen_buf);
}

static struct ch_storage *client_new_ch_storage(const char *path,
                                                StorageBackend backend)
{
    struct ch_storage *chns;
    if (backend == STORAGE_BACKEND__STORE_HDF5) {
        chns = hdf5_ch_storage_alloc(path, HDF5_DATASET_NAME);
    } else if (backend == STORAGE_BACKEND__STORE_RAW) {
        chns = raw_ch_storage_alloc(path, 0644);
    } else {
        assert(0);
        return NULL;
    }
    if (!chns) {
        log_ERR("can't open channel storage at %s: %m", path);
        return NULL;
    }
    return chns;
}

static int client_open_ch_storage(struct ch_storage *chns,
                                  StorageBackend backend)
{
    unsigned flags;
    if (backend == STORAGE_BACKEND__STORE_HDF5) {
        flags = H5F_ACC_TRUNC;
    } else if (backend == STORAGE_BACKEND__STORE_RAW) {
        flags = O_CREAT | O_RDWR | O_TRUNC;
    } else {
        assert(0);
        return -1;
    }
    if (ch_storage_open(chns, flags) == -1) {
        log_ERR("can't open channel storage at %s: %m",
                chns->ch_path);
        return -1;
    }
    return 0;
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
    if (cpriv->c_cmd) {
        control_command__free_unpacked(cpriv->c_cmd, NULL);
        cpriv->c_cmd = NULL;
    }
}

static void client_send_response(struct control_session *cs,
                                 ControlResponse *cr)
{
    struct client_priv *cpriv = cs->cpriv;
    size_t len = control_response__get_packed_size(cr);
    assert(len < CLIENT_CMD_MAX_SIZE); /* or WTF; honestly */
    size_t packed = control_response__pack(cr, cpriv->c_rsp_arr);
    client_cmd_len_t clen = client_cmd_hton((client_cmd_len_t)packed);
    bufferevent_write(cs->cbev, &clen, CLIENT_CMDLEN_SIZE);
    bufferevent_write(cs->cbev, cpriv->c_rsp_arr, packed);
    if (cr->type != CONTROL_RESPONSE__TYPE__ERR) {
        log_DEBUG("sending non-error ControlResponse type %d", cr->type);
    } else {
        log_DEBUG("sending error ControlResponse type");
    }
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
        log_DEBUG("got client request, but no data node is connected"); \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__NO_DNODE,        \
                        "not connected to data node");                  \
    } while (0)

#define CLIENT_RES_ERR_DAEMON(cs, msg) do {                             \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__DAEMON,          \
                        "internal daemon error: " msg);                 \
 } while (0)

#define CLIENT_RES_ERR_DAEMON_IO(cs, msg) do {                          \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__DAEMON_IO,       \
                        "internal daemon I/O error: " msg);             \
 } while (0)

#define CLIENT_RES_ERR_DAEMON_OOM(cs) do {                              \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__DAEMON,          \
                        "internal daemon error: out of memory");        \
 } while (0)

#define CLIENT_RES_ERR_C_VALUE(cs, msg) do {                           \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__C_VALUE,        \
                        "client value error: " msg); } while (0)

#define CLIENT_RES_ERR_C_PROTO(cs, msg) do {                           \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__C_PROTO,        \
                        "client protocol error: " msg); } while (0)

#define CLIENT_RES_ERR_D_PROTO(cs, msg) do {                           \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__D_PROTO,        \
                        "data node protocol error: " msg); } while (0)

#define CLIENT_RES_ERR_DNODE(cs, msg) do {                           \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__DNODE,        \
                        "data node error: " msg); } while (0)

#define CLIENT_RES_ERR_DNODE_ASYNC(cs) do {                            \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__DNODE_ASYNC,    \
                        "data node async error"); } while (0)

#define CLIENT_RES_ERR_DNODE_DIED(cs) do {                              \
        client_send_err(cs, CONTROL_RES_ERR__ERR_CODE__DNODE_DIED,      \
                        "data node connection closed unexpectedly");    \
    } while (0)

static void client_send_store_res(struct control_session *cs, short events)
{
    struct client_priv *cpriv = cs->cpriv;

    ControlCmdStore *store;
    ControlResponse cr = CONTROL_RESPONSE__INIT;
    ControlResStore res_store = CONTROL_RES_STORE__INIT;

    /* Decide how many samples we stored. */
    size_t nsamples = (cpriv->bs_nwritten_cache +
                       (cpriv->bs_restart_pending != -1 ?
                        (size_t)cpriv->bs_restart_pending : 0));

    /* Reset sample storage state to prepare for next storage command */
    store = cpriv->c_cmd->store;
    assert(cpriv->bs_cfg);
    assert(store);
    assert(store->has_backend);
    if (ch_storage_close(cpriv->bs_cfg->chns) == -1) {
        log_ERR("%s: can't close channel storage", __func__);
    }
    ch_storage_free(cpriv->bs_cfg->chns);
    free(cpriv->bs_cfg);
    cpriv->bs_cfg = NULL;
    cpriv->bs_expecting = 0;
    cpriv->bs_restarted = 0;
    client_unpend_restart(cs);
    cpriv->bs_nwritten_cache = 0;

    /* Send the result. */
    res_store.has_status = 1;
    res_store.has_nsamples = 1;
    res_store.nsamples = nsamples;
    res_store.path = cpriv->c_cmd->store->path;
    if (events & SAMPLE_BS_DONE) {
        res_store.status = CONTROL_RES_STORE__STATUS__DONE;
    } else if (events & SAMPLE_BS_ERR) {
        res_store.status = CONTROL_RES_STORE__STATUS__ERROR;
    } else if (events & SAMPLE_BS_PKTDROP) {
        res_store.status = CONTROL_RES_STORE__STATUS__PKTDROP;
    } else if (events & SAMPLE_BS_TIMEOUT) {
        res_store.status = CONTROL_RES_STORE__STATUS__TIMEOUT;
    } else {
        CLIENT_RES_ERR_DAEMON(cs, "can't determine storage result");
        assert(0);
        return;
    }
    cr.has_type = 1;
    cr.type = CONTROL_RESPONSE__TYPE__STORE_FINISHED;
    cr.store = &res_store;
    client_send_response(cs, &cr);
}

/********************************************************************
 * Shared helpers used by command processing routines
 */

static uint32_t client_get_data_addr4(struct control_session *cs,
                                      uint32_t *s_addr)
{
    struct sockaddr_in saddr = {
        .sin_family = AF_UNSPEC,
    };
    socklen_t addrlen = sizeof(saddr);
    if (sample_get_saddr(cs->smpl, AF_INET, (struct sockaddr*)&saddr,
                         &addrlen)) {
        log_WARNING("can't read dnode data socket address");
        return -1;
    }
    assert(saddr.sin_family == AF_INET);
    *s_addr = htonl(saddr.sin_addr.s_addr);
    return 0;
}

static int client_get_dsock_info(struct control_session *cs,
                                 uint32_t *ipv4_s_addr,
                                 uint32_t *iface_mac48_h,
                                 uint32_t *iface_mac48_l)
{
    uint8_t dsock_m48[6];
    if ((client_get_data_addr4(cs, ipv4_s_addr) ||
         sample_get_mac48(cs->smpl, dsock_m48))) {
        return -1;
    }
    *iface_mac48_h = (((uint32_t)dsock_m48[0] << 8) |
                      (uint32_t)dsock_m48[1]);
    *iface_mac48_l = (((uint32_t)dsock_m48[2] << 24) |
                      ((uint32_t)dsock_m48[3] << 16) |
                      ((uint32_t)dsock_m48[4] << 8) |
                      (uint32_t)dsock_m48[5]);
    return 0;
}

static void client_clear_dnode_addr_storage(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    cpriv->dn_addr_in.sin_family = AF_INET;
    cpriv->dn_addr_in.sin_port = 0;
    cpriv->dn_addr_in.sin_addr.s_addr = 0;
    memset(&cpriv->dn_addr_in.sin_zero, 0,
           sizeof(cpriv->dn_addr_in.sin_zero));
}

static int client_res_updates_dnode_addr(struct raw_cmd_res *res)
{
    /* TODO update this for IPv6 */
    return (res->r_type == RAW_RTYPE_UDP &&
            (res->r_addr == RAW_RADDR_UDP_SRC_IP4 ||
             res->r_addr == RAW_RADDR_UDP_SRC_IP4_PORT));
}

/* NOT SYNCHRONIZED
 *
 * For commands which call client_add_network_txns(), update data node
 * address storage when the appropriate responses are received. If an
 * attempt to do so fails, send an error result and return -1. */
static int client_update_dnode_addr_storage(struct control_session *cs,
                                            size_t txn)
{
    struct client_priv *cpriv = cs->cpriv;
    struct raw_cmd_res *res = ctxn_res(cs->ctl_txns + txn);

    if (!client_res_updates_dnode_addr(res)) {
        return 0;
    }

    if (res->r_addr == RAW_RADDR_UDP_SRC_IP4) {
        cpriv->dn_addr_in.sin_addr.s_addr = htonl(res->r_val);
        return 0;
    } else if (res->r_addr == RAW_RADDR_UDP_SRC_IP4_PORT) {
        if (res->r_val > UINT16_MAX) {
            log_WARNING("data node source IPv4 port %u is invalid",
                        res->r_val);
            CLIENT_RES_ERR_DNODE(cs, "invalid data port specified");
            return -1;
        }
        cpriv->dn_addr_in.sin_port = htons((uint16_t)res->r_val);

        /* client_add_network_txns() gets address, then port, so we've
         * got the entire address now. */
        if (sample_set_addr(cs->smpl, (struct sockaddr*)&cpriv->dn_addr_in,
                            SAMPLE_ADDR_DNODE)) {
            CLIENT_RES_ERR_DAEMON(cs, "can't configure data node address");
            return -1;
        }
    }
    return 0;
}

/* NOT SYNCHRONIZED
 *
 * For commands which check SATA status, ensure that SATA status
 * reports RAW_SATA_STATUS_DEVICE_READY. If not, return -1.
 */
static int client_check_sata_device_ready(struct control_session *cs, size_t txn)
{
    struct raw_cmd_res *res = ctxn_res(cs->ctl_txns + txn);
    if (res->r_type == RAW_RTYPE_SATA &&
        res->r_addr == RAW_RADDR_SATA_STATUS &&
        !(res->r_val & RAW_SATA_STATUS_DEVICE_READY)) {
        CLIENT_RES_ERR_DNODE(cs, "SATA device is not ready");
        return -1;
    }
    return 0;
}

/********************************************************************
 * Sample handler storage callbacks
 *
 * TODO: these are messy; clean them up. In particular, we don't need
 * bs_restart_pending and bs_pending_events -- we can tell the former
 * from the latter, e.g. This would also let us go down to a single
 * schedule function, etc.
 */

/* For the sample.h API. */
static void client_sample_store_callback(short events, size_t nwritten,
                                         void *csvp);

static void client_update_bs_status(struct control_session *cs,
                                    size_t nwritten)
{
    struct client_priv *cpriv = cs->cpriv;
    cpriv->bs_nwritten_cache += nwritten;
    cpriv->bs_cfg->nsamples -= nwritten;
    cpriv->bs_cfg->start_sample += nwritten;
}

/* For activating a restart from the background thread. */
static void client_sample_restart_callback(__unused evutil_socket_t ignored,
                                           __unused short events_ignored,
                                           void *csvp)
{
    log_DEBUG("%s", __func__);
    struct control_session *cs = csvp;
    struct client_priv *cpriv = cs->cpriv;
    assert(client_is_response_pending(cs));
    assert(cpriv->bs_restart_pending != -1);
    short events = cpriv->bs_pending_events;
    cpriv->bs_pending_events = 0;
    client_sample_store_callback(events, cpriv->bs_restart_pending, csvp);
}

/* For activating a response from the background thread. */
static void client_sample_done_callback(__unused evutil_socket_t ignored,
                                        __unused short events_ignored,
                                        void *csvp)
{
    log_DEBUG("%s", __func__);
    struct control_session *cs = csvp;
    struct client_priv *cpriv = cs->cpriv;
    assert(client_is_response_pending(cs));
    assert(cpriv->bs_restart_pending == -1);
    short events = cpriv->bs_pending_events;
    cpriv->bs_pending_events = 0;
    client_sample_store_callback(events, 0, csvp);
}

static inline void client_do_schedule_prechecks(struct control_session *cs)
{
    assert(!client_is_response_pending(cs));
    assert(control_is_txn_timeout_pending(cs));
    assert(!cpriv(cs)->bs_response_pend_evt);
    assert(cpriv(cs)->bs_pending_events == 0);
}

/* Postpone a sample storage restart until after a pending
 * transaction's response is received.
 *
 * NOT SYNCHRONIZED (mtx) */
static void client_schedule_sample_store_restart(struct control_session *cs,
                                                 short events,
                                                 size_t nwritten)
{
    struct client_priv *cpriv = cs->cpriv;
    client_do_schedule_prechecks(cs);
    log_DEBUG("%s: waiting to begin restart", __func__);
    cpriv->bs_restart_pending = nwritten;
    cpriv->bs_response_pend_evt = event_new(cs->base, -1, SAMPLE_BS_PKTDROP,
                                           client_sample_restart_callback, cs);
    cpriv->bs_pending_events = events;
    if (!cpriv->bs_response_pend_evt) {
        log_ERR("out of memory; can't alloc sample restart event");
        exit(EXIT_FAILURE);     /* FIXME allocate at start time instead */
    }
}

/* Postpone a sample storage restart until after a pending
 * transaction's response is received.
 *
 * NOT SYNCHRONIZED (mtx) */
static void client_schedule_sample_store_finished(struct control_session *cs,
                                                  short events)
{
    struct client_priv *cpriv = cs->cpriv;
    client_do_schedule_prechecks(cs);
    log_DEBUG("%s: waiting to send store response", __func__);
    cpriv->bs_response_pend_evt = event_new(cs->base, -1, 0,
                                            client_sample_done_callback, cs);
    cpriv->bs_pending_events = events;
    if (!cpriv->bs_response_pend_evt) {
        log_ERR("out of memory, can't alloc sample restart event");
        exit(EXIT_FAILURE);     /* FIXME allocate at start time instead */
    }
}

/* Restart a sample storage operation which dropped a packet.
 *
 * NOT SYNCHRONIZED (mtx) */
static void client_do_sample_store_restart(struct control_session *cs,
                                           size_t nwritten)
{
    /* You can't call this while transactions are ongoing. */

    /*
     * Since this is invoked from the callback we gave
     * sample_expect_bsamps(), we can't call it again
     * ourselves. Instead, update cpriv->bs_cfg and related fields,
     * update the restart count, clear the restart pending flag if
     * necessary, and get the worker to restart the transfer for
     * us.
     */
    struct client_priv *cpriv = cs->cpriv;
    assert(nwritten < cpriv->bs_cfg->nsamples);
    assert(cpriv->bs_cfg->start_sample >= 0);
    client_update_bs_status(cs, nwritten);
    control_clear_transactions(cs, 1);
    if (nwritten || !cpriv->bs_restarted) {
        cpriv->bs_restarted = 1;
    } else {
        cpriv->bs_restarted++;
    }
    if (client_is_response_pending(cs)) {
        assert(cpriv->bs_restart_pending != -1);
        assert(cpriv->bs_response_pend_evt);
        client_unpend_restart(cs);
    }
    if (cpriv->bs_restarted > MAX_FAILED_STORAGE_RETRIES) {
        /* Actually, that's too many retry attempts; sample
         * storage is apparently hosed. Cut this off now. */
        log_WARNING("restarted storage %u times; not retrying again.",
                    MAX_FAILED_STORAGE_RETRIES);
        client_send_store_res(cs, SAMPLE_BS_ERR);
    } else {
        log_DEBUG("restarting sample storage: "
                  "nwritten=%zu, nsamples=%zu, start_sample=%zd",
                  cpriv->bs_nwritten_cache, cpriv->bs_cfg->nsamples,
                  cpriv->bs_cfg->start_sample);
        cs->wake_why |= CONTROL_WHY_CLIENT_CMD;
        control_must_signal(cs);
    }
}

/* Used so the sample.h API can report sample storage results.  */
static void client_sample_store_callback(short events, size_t nwritten,
                                         void *csvp)
{
    struct control_session *cs = csvp;
    struct client_priv *cpriv;
    ControlCmdStore *store;

    control_must_lock(cs);
    cpriv = cs->cpriv;
    assert(cpriv->c_cmd);
    store = cpriv->c_cmd->store;
    assert(store);

    if (client_is_response_pending(cs) && cpriv->bs_restart_pending != -1) {
        /* We're being called again after a previous restart attempt
         * couldn't go forward due to an unfinished transaction. */
        assert(!control_is_txn_timeout_pending(cs));
        assert((size_t)(cpriv->bs_restart_pending) == nwritten);
        client_do_sample_store_restart(cs, nwritten);
    } else if (store->has_start_sample && (events & SAMPLE_BS_PKTDROP)) {
        /* We're storing canned samples and we dropped a packet.
         * Update and restart the transfer. */
        if (control_is_txn_timeout_pending(cs)) {
            /* Actually, wait for the transaction to complete or time
             * out, so we don't get confused when we get its
             * response. */
            client_schedule_sample_store_restart(cs, events, nwritten);
        } else {
            client_do_sample_store_restart(cs, nwritten);
        }
    } else {
        /* Otherwise, we're done with this command. Send the response
         * now if we can, or after we've finished our next register
         * I/O transaction otherwise. */
        cpriv->bs_nwritten_cache += nwritten;
        if (control_is_txn_timeout_pending(cs)) {
            client_schedule_sample_store_finished(cs, events);
        } else {
            client_send_store_res(cs, events);
        }
    }
    control_must_unlock(cs);
}

/********************************************************************
 * Main thread control_ops callbacks
 */

static int client_start(struct control_session *cs)
{
    struct client_priv *priv = NULL;
    struct evbuffer *c_pbuf = NULL;
    struct evbuffer *c_pbuflen_buf = NULL;

    priv = malloc(sizeof(struct client_priv));
    if (!priv) {
        goto bail;
    }
    c_pbuf = evbuffer_new();
    if (!c_pbuf) {
        goto bail;
    }
    c_pbuflen_buf = evbuffer_new();
    if (!c_pbuflen_buf) {
        goto bail;
    }

    priv->c_cmd = NULL;
    priv->c_rsp = NULL;
    priv->c_pbuf = c_pbuf;
    priv->c_pbuflen_buf = c_pbuflen_buf;
    priv->bs_cfg = NULL;
    priv->bs_expecting = 0;
    priv->bs_restarted = 0;
    priv->bs_restart_pending = -1;
    priv->bs_response_pend_evt = NULL;
    priv->bs_pending_events = 0;
    priv->bs_nwritten_cache = 0;
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
    if (c_pbuflen_buf) {
        evbuffer_free(c_pbuflen_buf);
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

static void client_ensure_clean_locked(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    assert(cpriv);
    assert(cpriv->c_cmd == NULL);
    assert(cpriv->c_pbuf);
    assert(evbuffer_get_length(cpriv->c_pbuf) == 0);
    assert(evbuffer_get_length(cpriv->c_pbuflen_buf) == 0);
    assert(cpriv->c_pbuflen == CLIENT_CMDLEN_WAITING);
    assert(cs->ctl_txns == NULL);
    assert(cs->ctl_cur_txn == -1);
}

static int client_open(struct control_session *cs,
                       __unused evutil_socket_t control_sockfd)
{
    client_ensure_clean_locked(cs);
    return 0;
}

static void client_close(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    assert(cpriv);
    control_must_lock(cs);
    /* FIXME be smarter; don't call this here. Halting sample storage
     * needs to wait for blocking I/O to finish. */
    client_halt_ongoing_transfer(cs);
    client_reset_state_locked(cs);
    client_ensure_clean_locked(cs);
    control_must_unlock(cs);
}

static int client_got_entire_pbuf(struct control_session *cs)
{
    struct evbuffer *evb = bufferevent_get_input(cs->cbev);
    struct client_priv *cpriv = cs->cpriv;

    /* If waiting for a length prefix, buffer it into
     * cpriv->c_pbuflen_buf. If that fills the buffer, unpack it into
     * cs->c_pbuflen. */
    if (cpriv->c_pbuflen == CLIENT_CMDLEN_WAITING) {
        size_t cmdlen_buflen = evbuffer_get_length(cpriv->c_pbuflen_buf);
        evbuffer_remove_buffer(evb, cpriv->c_pbuflen_buf,
                               CLIENT_CMDLEN_SIZE - cmdlen_buflen);
        assert(evbuffer_get_length(cpriv->c_pbuflen_buf) <= CLIENT_CMDLEN_SIZE);
        if (evbuffer_get_length(cpriv->c_pbuflen_buf) < CLIENT_CMDLEN_SIZE) {
            goto out;
        } else { /* length(cs->c_pbuflen_buf) == CLIENT_CMDLEN_SIZE */
            evbuffer_remove(cpriv->c_pbuflen_buf, &cpriv->c_pbuflen,
                            CLIENT_CMDLEN_SIZE);
            cpriv->c_pbuflen = client_cmd_ntoh(cpriv->c_pbuflen);
        }
    }

    /* Sanity-check the received protocol buffer length. */
    if (cpriv->c_pbuflen > CLIENT_CMD_MAX_SIZE) {
        return -1;              /* Too long; kill the connection. */
    }

    /* We've received a complete length prefix, so shove any
     * new/additional bits into cpriv->c_pbuf. */
    size_t pbuf_len = evbuffer_get_length(cpriv->c_pbuf);
    evbuffer_remove_buffer(evb, cpriv->c_pbuf, cpriv->c_pbuflen - pbuf_len);

 out:
    return (cpriv->c_pbuflen != CLIENT_CMDLEN_WAITING &&
            evbuffer_get_length(cpriv->c_pbuf) == (unsigned)cpriv->c_pbuflen);
}

/* NOT SYNCHRONIZED */
static void client_reset_for_next_pbuf(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    cpriv->c_pbuflen = CLIENT_CMDLEN_WAITING;
    assert(evbuffer_get_length(cpriv->c_pbuf) == 0);
    assert(evbuffer_get_length(cpriv->c_pbuflen_buf) == 0);
}

static int client_read(struct control_session *cs)
{
    int ret = CONTROL_WHY_NONE;
    struct client_priv *cpriv = cs->cpriv;

    control_must_lock(cs);

    if (cpriv->c_cmd || cs->ctl_txns) {
        /* There's an existing command we're still dealing with; the
         * client shouldn't have sent us a new one. Kill the
         * connection so we don't have to bother queueing
         * responses. */
        ret = -1;
        goto done;
    }

    /*
     * Try to pull an entire protocol buffer out of cs->dbev.
     */
    switch (client_got_entire_pbuf(cs)) {
    case 1:
        break; /* Success */
    case 0:
        goto done; /* Still waiting */
    case -1:
        ret = -1;        /* Oops, time to die */
        goto done;
    default:
        assert(0);
        log_ERR("%s: can't happen", __func__);
        drain_evbuf(bufferevent_get_input(cs->cbev));
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
         * Kill the connection. We can queue commands later. */
        ret = -1;
        goto done;
    }
    ret = CONTROL_WHY_CLIENT_CMD;

 done:
    control_must_unlock(cs);
    return ret;
}

/* NOT SYNCHRONIZED (mtx) */
static void client_partner_closed(struct control_session *cs)
{
    if (!cs->ctl_txns) {
        /* We weren't in the middle of anything, so there's nothing to do. */
        return;
    }

    control_clear_transactions(cs, 1);
    if (client_is_response_pending(cs)) {
        /* We were waiting for a transaction to finish so we could
         * restart some storage, but the data node connection died
         * (e.g. due to timeout). The client still needs to know the
         * result. */
        struct client_priv *cpriv = cs->cpriv;
        event_active(cpriv->bs_response_pend_evt, 0, 0);
    } else {
        CLIENT_RES_ERR_DNODE_DIED(cs);
    }
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

/* NOT SYNCHRONIZED */
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
        LOCAL_DEBUG("write raw_cmd_req doesn't match raw_cmd_res; "
                    "r_type=%s, r_addr=%s",
                    raw_r_type_str(req->r_type),
                    raw_r_addr_str(req->r_type, req->r_addr));
        if (req->r_id != res->r_id) {
            LOCAL_DEBUG("req->r_id=%u, res->r_id=%u", req->r_id, res->r_id);
        } else if (req->r_type != res->r_type) {
            LOCAL_DEBUG("req->r_type=%u, res->r_type=%u", req->r_type,
                        res->r_type);
        } else if (req->r_addr != res->r_addr) {
            LOCAL_DEBUG("req->r_addr=%u, res->r_addr=%u", req->r_addr,
                        res->r_addr);
        } else {
            assert(req->r_val != res->r_val);
            LOCAL_DEBUG("req->r_val=%u, res->r_val=%u", req->r_val,
                        res->r_val);
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

#define CLIENT_N_NET_TXNS 5
static ssize_t client_add_network_txns(struct control_session *cs,
                                       struct control_txn *txns,
                                       size_t ntxns)
{
    struct client_priv *cpriv = cs->cpriv;

    /* IMPORTANT: the callers of this function (and their callers)
     * rely on the order in which these transactions are set. Don't
     * change it! */
    if (ntxns < CLIENT_N_NET_TXNS) {
        if (!cpriv->bs_restarted) {
            CLIENT_RES_ERR_DAEMON(cs, "can't set up network transactions");
        }
        return -1;
    }
    /* Get the daemon data socket's IPv4 and MAC48 addresses, which we
     * need to initialize dnode registers. */
    uint32_t dsock_ipv4, m48h, m48l;
    if (client_get_dsock_info(cs, &dsock_ipv4, &m48h, &m48l) == -1) {
        if (!cpriv->bs_restarted) {
            CLIENT_RES_ERR_DAEMON(cs, "internal network error");
        }
        return -1;
    }
    size_t txoff = 0;
    /* Read the data node's UDP IPv4 address and port. */
    client_udp_r(txns + txoff++, RAW_RADDR_UDP_SRC_IP4);
    client_udp_r(txns + txoff++, RAW_RADDR_UDP_SRC_IP4_PORT);
    /* Set UDP IPv4 destination register. */
    client_udp_w(txns + txoff++, RAW_RADDR_UDP_DST_IP4, dsock_ipv4);
    /* Set UDP MAC destination registers */
    client_udp_w(txns + txoff++, RAW_RADDR_UDP_DST_MAC_H, m48h);
    client_udp_w(txns + txoff++, RAW_RADDR_UDP_DST_MAC_L, m48l);

    assert(txoff == CLIENT_N_NET_TXNS);
    client_clear_dnode_addr_storage(cs);
    return (ssize_t)txoff;
}

/* NOT SYNCHRONIZED
 *
 * For use within thread callback only.
 */
static void client_start_txns(struct control_session *cs,
                              struct control_txn *txns,
                              size_t txno,
                              size_t ntxns)
{
    assert(txno <= ntxns);
    control_set_transactions(cs, txns, txno, 1);
    cs->wake_why |= CONTROL_WHY_DNODE_TXN;
}

/* NOT SYNCHRONIZED */
static int client_start_txns_stream(struct control_session *cs,
                                    int force_daq_reset,
                                    uint32_t daq_udp_mode)
{
    const size_t max_ntxns = CLIENT_N_NET_TXNS + 10;

    struct control_txn *txns = malloc(max_ntxns * sizeof(struct control_txn));
    size_t txno = 0;
    if (!txns) {
        CLIENT_RES_ERR_DAEMON_OOM(cs);
        return -1;
    }

    /* Read/write the various daemon/data node network addresses. */
    ssize_t nstat = client_add_network_txns(cs, txns, max_ntxns);
    if (nstat == -1) {
        return -1;
    }
    txno = (size_t)nstat;
    if (force_daq_reset) {
        /* Write 0 (STOP) to UDP and DAQ enable registers */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_UDP_ENABLE, 0);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_ENABLE, 0);
        client_udp_w(txns + txno++, RAW_RADDR_UDP_ENABLE, 0);
        /* Toggle reset line by writing 1/0 to DAQ FIFO flags register
         * (bring reset line high/low) */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_FIFO_FLAGS, 1);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_FIFO_FLAGS, 0);
        /* Setup payload length (packet type) for UDP core */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_UDP_MODE, daq_udp_mode);
        /* Set UDP module to stream from DAQ (not SATA) */
        client_udp_w(txns + txno++,
                     RAW_RADDR_UDP_MODE, RAW_UDP_MODE_UDP);
        /* Enable UDP module */
        client_udp_w(txns + txno++, RAW_RADDR_UDP_ENABLE, 1);
        /* Enable DAQ module */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_UDP_ENABLE, 1);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_ENABLE, 1);
    } else {
        client_udp_w(txns + txno++, RAW_RADDR_UDP_ENABLE, 0);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_UDP_ENABLE, 0);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_FIFO_FLAGS, 1);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_FIFO_FLAGS, 0);
        client_udp_w(txns + txno++,
                     RAW_RADDR_UDP_MODE, RAW_UDP_MODE_UDP);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_UDP_MODE, daq_udp_mode);
        client_udp_w(txns + txno++, RAW_RADDR_UDP_ENABLE, 1);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_UDP_ENABLE, 1);
    }

    /* Enable the deferred work. */
    client_start_txns(cs, txns, txno, max_ntxns);
    return 0;
}

/* NOT SYNCHRONIZED
 *
 * If we're currently handling a restarted storage command, no
 * response will be sent on error. Otherwise, we send an error
 * response if we can't start the storage register I/O transactions.
 */
static int client_start_txns_store(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    const size_t ntxns = CLIENT_N_NET_TXNS + 14;
    struct control_txn *txns = malloc(ntxns * sizeof(struct control_txn));
    size_t txno = 0;
    if (!txns) {
        if (!cpriv->bs_restarted) {
            CLIENT_RES_ERR_DAEMON_OOM(cs);
        }
        return -1;
    }

    /* Read/write the various daemon/data node network addresses. */
    ssize_t nstat = client_add_network_txns(cs, txns, ntxns);
    if (nstat == -1) {
        if (!cpriv->bs_restarted) {
            CLIENT_RES_ERR_DAEMON(cs, "can't set up store transactions");
        }
        return -1;
    }
    txno = (size_t)nstat;

    /* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
     *
     * THE REST OF THE STORAGE PROCESSING CODE RELIES ON THESE
     * TRANSACTIONS TAKING PLACE IN THE GIVEN ORDER. DO NOT CHANGE IT.
     *
     * XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
     */

    /* Stop SATA, DAQ, and UDP modules. */
    client_sata_w(txns + txno++, RAW_RADDR_SATA_MODE, RAW_SATA_MODE_WAIT);
    client_daq_w(txns + txno++, RAW_RADDR_DAQ_UDP_ENABLE, 0);
    client_udp_w(txns + txno++, RAW_RADDR_UDP_ENABLE, 0);
    /* Reset SATA-UDP and SATA read FIFOs by toggling reset line */
    client_sata_w(txns + txno++, RAW_RADDR_SATA_UDP_FIFO_RST, 1);
    client_sata_w(txns + txno++, RAW_RADDR_SATA_UDP_FIFO_RST, 0);
    client_sata_w(txns + txno++, RAW_RADDR_SATA_R_FIFO_RST, 1);
    client_sata_w(txns + txno++, RAW_RADDR_SATA_R_FIFO_RST, 0);
    /* Check SATA device ready flag */
    client_sata_r(txns + txno++, RAW_RADDR_SATA_STATUS);
    /* Set SATA read index and length.
     *
     * If the user wants all the samples, ensure that we read how many
     * there are first. We'll overwrite the incorrect nsamples
     * transaction request when handling responses in that case. */
    client_sata_w(txns + txno++,
                  RAW_RADDR_SATA_R_IDX, cpriv->bs_cfg->start_sample);
    if (cpriv->bs_cfg->nsamples == 0) {
        client_sata_r(txns + txno++, RAW_RADDR_SATA_W_IDX);
    }
    client_sata_w(txns + txno++,
                  RAW_RADDR_SATA_R_LEN, cpriv->bs_cfg->nsamples);
    /* Configure UDP to stream from SATA */
    client_udp_w(txns + txno++, RAW_RADDR_UDP_MODE, RAW_UDP_MODE_SATA);
    /* Enable UDP module. */
    client_udp_w(txns + txno++, RAW_RADDR_UDP_ENABLE, 1);
    /* Enable SATA reads */
    client_sata_w(txns + txno++, RAW_RADDR_SATA_MODE, RAW_SATA_MODE_READ);

    client_start_txns(cs, txns, txno, ntxns);
    return 0;
}

/* Check that the last transaction succeeded. Send an error response
 * and return -1 if it didn't. Return 0 if the transaction
 * succeeded. */
static int client_ensure_txn_ok(struct control_session *cs,
                                const char *cmd_str)
{
    if (!client_last_txn_succeeded(cs)) {
        log_WARNING("transaction %zd/%zu failed while processing %s",
                    cs->ctl_cur_txn, cs->ctl_n_txns - 1, cmd_str);
        CLIENT_RES_ERR_DNODE(cs, "failed I/O transaction");
        return -1;
    }
    return 0;
}

/*
 * Request processing
 */

typedef void (*cmd_proc_fn)(struct control_session*);

/*
 * Advance to the next control transaction.
 *
 * If there are more transactions to come, set the wake_why flag so
 * the data node handler knows it's got work to do.
 */
static int client_start_next_txn(struct control_session *cs)
{
    cs->ctl_cur_txn++;
    if ((size_t)cs->ctl_cur_txn != cs->ctl_n_txns) {
        cs->wake_why |= CONTROL_WHY_DNODE_TXN;
        return 0;
    }
    return 1;
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
    if (!reg_io->has_module) {
        CLIENT_RES_ERR_C_PROTO(cs, "missing RegisterIO type field");
        return;
    }

    /* A little evil macro to save typing. */
    uint16_t reg_addr;
#define REG_IO_CASE(lcase, ucase)                                       \
    MODULE__MOD_ ## ucase:                                              \
        if (!reg_io->has_ ## lcase) {                                   \
            CLIENT_RES_ERR_C_PROTO(cs,                                 \
                                   "missing " #lcase " register address"); \
            return;                                                     \
        }                                                               \
        reg_addr = reg_io->lcase;                                       \
        break

    switch (reg_io->module) {
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
    raw_req_init(&txn->req_pkt, ioflag, 0, reg_io->module, reg_addr, ioval);
    control_set_transactions(cs, txn, 1, 1);
    cs->wake_why |= CONTROL_WHY_DNODE_TXN;
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
    reg_io.has_module = 1;
    reg_io.module = res->r_type;
#if (RAW_RTYPE_NTYPES - 1) != RAW_RTYPE_GPIO /* future-proofing */
#error "changes to RAW_RTYPE_* require client code updates"
#endif
    switch (res->r_type) {
    case RAW_RTYPE_ERR:
        reg_io.has_err = 1;
        reg_io.err = res->r_addr;
        break;
    case RAW_RTYPE_CENTRAL:
        reg_io.has_central = 1;
        reg_io.central = res->r_addr;
        break;
    case RAW_RTYPE_SATA:
        reg_io.has_sata = 1;
        reg_io.sata = res->r_addr;
        break;
    case RAW_RTYPE_DAQ:
        reg_io.has_daq = 1;
        reg_io.daq = res->r_addr;
        break;
    case RAW_RTYPE_UDP:
        reg_io.has_udp = 1;
        reg_io.udp = res->r_addr;
        break;
    case RAW_RTYPE_GPIO:
        reg_io.has_gpio = 1;
        reg_io.gpio = res->r_addr;
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

static void client_process_cmd_stream(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    ControlCmdStream *stream = cpriv->c_cmd->stream;

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

    /* Set defaults */
    if (!stream->has_sample_type) {
        stream->sample_type = SAMPLE_TYPE__BOARD_SUBSAMPLE;
    }

    /*
     * Reconfigure sample conversion address/port if necessary
     */
    if (has_addr) {
        struct sockaddr_in caddr = {
            .sin_family = AF_INET,
            .sin_port = htons((uint16_t)stream->dest_udp_port),
            .sin_addr.s_addr = htonl(stream->dest_udp_addr4),
        };
        memset(&caddr.sin_zero, 0, sizeof(caddr.sin_zero));
        if (sample_set_addr(cs->smpl, (struct sockaddr*)&caddr,
                            SAMPLE_ADDR_CLIENT)) {
            CLIENT_RES_ERR_DAEMON(cs, "can't set destination address");
            return;
        }
    }
    /* If this is just a reconfigure command, then we're done here. */
    if (!stream->has_enable) {
        client_send_success(cs);
        return;
    }

    /*
     * Prepare transactions
     */
    if (stream->enable) {
        client_clear_dnode_addr_storage(cs);
        uint32_t daq_udp_mode;
        switch (stream->sample_type) {
        case SAMPLE_TYPE__BOARD_SUBSAMPLE: /* fall through */
        case SAMPLE_TYPE__BOARD_SUBSAMPLE_RAW:
            daq_udp_mode = RAW_DAQ_UDP_MODE_BSUB;
            break;
        case SAMPLE_TYPE__BOARD_SAMPLE: /* fall through */
        case SAMPLE_TYPE__BOARD_SAMPLE_RAW:
            daq_udp_mode = RAW_DAQ_UDP_MODE_BSMP;
            break;
        default:
            CLIENT_RES_ERR_C_VALUE(cs, "unknown sample_type");
            return;
        }
        int force_daq_reset = (stream->has_force_daq_reset ?
                               stream->force_daq_reset : 0);
        client_start_txns_stream(cs, force_daq_reset, daq_udp_mode);
    } else {
        /* Note: these transactions allow live storage to continue. */
        const size_t ntxns = 4;
        struct control_txn *txns = malloc(ntxns * sizeof(struct control_txn));
        size_t txno = 0;
        if (!txns) {
            CLIENT_RES_ERR_DAEMON(cs, "out of memory");
            return;
        }
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_UDP_ENABLE, 0);
        client_udp_w(txns + txno++, RAW_RADDR_UDP_ENABLE, 0);
        /* Toggle reset line by writing 1/0 to DAQ FIFO flags register
         * (bring reset line high/low) */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_FIFO_FLAGS, 1);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_FIFO_FLAGS, 0);
        client_start_txns(cs, txns, txno, ntxns);
    }
}

static void client_process_res_stream(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    ControlCmdStream *stream = cpriv->c_cmd->stream;

    assert(stream->has_enable);

    if (client_ensure_txn_ok(cs, "ControlCmdStream") == -1) {
        return;
    }

    /*
     * Deal with any register values we needed to read.
     */
    if (stream->enable &&
        client_update_dnode_addr_storage(cs, cs->ctl_cur_txn) == -1) {
        return;
    }

    /* Are there more transactions? */
    if (!client_start_next_txn(cs)) {
        return;                 /* Yes. */
    }

    /*
     * That's the last transaction. Finish up and send the success
     * result.
     */
    if (stream->enable &&
        sample_set_addr(cs->smpl, (struct sockaddr*)&cpriv->dn_addr_in,
                        SAMPLE_ADDR_DNODE)) {
        CLIENT_RES_ERR_DAEMON(cs, "can't configure data node address");
        return;
    }
    SampleType stype = stream->sample_type;
    enum sample_forward fwd = !stream->enable ? SAMPLE_FWD_NOTHING :
        (stype == SAMPLE_TYPE__BOARD_SAMPLE ? SAMPLE_FWD_BSMP :
         stype == SAMPLE_TYPE__BOARD_SUBSAMPLE ? SAMPLE_FWD_BSUB :
         stype == SAMPLE_TYPE__BOARD_SUBSAMPLE_RAW ? SAMPLE_FWD_BSUB_RAW :
         stype == SAMPLE_TYPE__BOARD_SAMPLE_RAW ? SAMPLE_FWD_BSMP_RAW :
         SAMPLE_FWD_NOTHING);
    if (fwd == SAMPLE_FWD_NOTHING && stream->enable) {
        CLIENT_RES_ERR_C_PROTO(cs, "unknown sample_type");
        return;
    }
    if (sample_cfg_forwarding(cs->smpl, fwd)) {
        CLIENT_RES_ERR_DAEMON(cs, "can't configure data forwarding");
        return;
    }
    client_send_success(cs);
}

static void client_process_cmd_store(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    ControlCmdStore *store = cpriv->c_cmd->store;
    struct ch_storage *chns = NULL;
    int chns_is_open = 0;
    struct sample_bsamp_cfg *bs_cfg = NULL;

    /* Check that the command is well-formed. */
    if (!store) {
        assert(!cpriv->bs_restarted);
        CLIENT_RES_ERR_C_PROTO(cs, "missing store command");
        goto bail;
    }
    if (!store->path) {
        assert(!cpriv->bs_restarted);
        CLIENT_RES_ERR_C_PROTO(cs, "missing path field");
        goto bail;
    }
    if (!store->has_nsamples && !store->has_start_sample) {
        CLIENT_RES_ERR_C_PROTO(cs, "nsamples and start_sample both omitted");
        goto bail;
    }

    /* Massage the command to set defaults */
    if (!store->has_backend) {
        store->has_backend = 1;
        store->backend = DEFAULT_STORAGE_BACKEND;
    }

    if (!cpriv->bs_restarted) {
        /* If this isn't a restarted storage operation, then create
         * the channel storage object, and initialize the board sample
         * configuration. */

        /* Pull the fields we need out of the command.
         *
         * nsamples == 0 is illegal, so we use that to indicate that we
         * need to use the total number of samples available. */
        size_t nsamples = store->has_nsamples ? store->nsamples : 0;
        ssize_t start_sample = (store->has_start_sample ?
                                (ssize_t)store->start_sample : -1);

        assert(!cpriv->bs_cfg);
        chns = client_new_ch_storage(store->path, store->backend);
        if (!chns) {
            CLIENT_RES_ERR_DAEMON_OOM(cs);
            goto bail;
        }
        if (client_open_ch_storage(chns, store->backend) == -1) {
            CLIENT_RES_ERR_DAEMON_IO(cs, "can't open channel storage");
            goto bail;
        }
        chns_is_open = 1;
        bs_cfg = malloc(sizeof(struct sample_bsamp_cfg));
        if (!bs_cfg) {
            ch_storage_free(chns);
            CLIENT_RES_ERR_DAEMON_OOM(cs);
            goto bail;
        }
        bs_cfg->nsamples = nsamples;
        bs_cfg->start_sample = start_sample;
        bs_cfg->chns = chns;
        cpriv->bs_cfg = bs_cfg;
    } else {
        /* Otherwise, we're restarting a channel storage operation
         * that dropped a packet. */
        assert(cpriv->bs_cfg);
        chns_is_open = 1;       /* it was opened previously. */
    }

    /* Prepare the transactions. */
    int storing_live_data = !store->has_start_sample;
    if (storing_live_data) {
        const int force_daq_reset = 0;
        if (client_start_txns_stream(cs, force_daq_reset,
                                     RAW_DAQ_UDP_MODE_BSMP) == -1) {
            goto bail;
        }
    } else {
        if (client_start_txns_store(cs) == -1) {
            if (cpriv->bs_restarted) {
                /* If we failed to restart the storage, the client needs
                 * to know how far along we got. */
                client_send_store_res(cs, SAMPLE_BS_ERR);
            } else {
                /* Otherwise, report failure to start the storage. */
                CLIENT_RES_ERR_DAEMON(cs, "can't set up storage transactions");
            }
            goto bail;
        }
    }

    return;
 bail:
    if (chns_is_open) {
        ch_storage_close(chns);
    }
    if (chns) {
        ch_storage_free(chns);
    }
    if (bs_cfg) {
        if (bs_cfg == cpriv->bs_cfg) {
            cpriv->bs_cfg = NULL;
        }
        free(bs_cfg);
    }
}

static void client_process_res_store(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;

    if (client_is_response_pending(cs)) {
        log_DEBUG("%s: transaction finished, handling pending callback",
                  __func__);
        control_clear_transactions(cs, 1);
        event_active(cpriv->bs_response_pend_evt, 0, 0);
        return;
    } else if (cpriv->bs_restarted) {
        if (!client_last_txn_succeeded(cs)) {
            /* We failed a restart. The client still need to know how
             * many samples we successfully saved. */
            client_send_store_res(cs, SAMPLE_BS_ERR);
            return;
        }
    } else if (client_ensure_txn_ok(cs, "ControlCmdStore") == -1) {
        if (cpriv->bs_expecting) {
            sample_reject_bsamps(cs->smpl);
            cpriv->bs_expecting = 0;
            cpriv->bs_restarted = 0;
            cpriv->bs_nwritten_cache = 0;
        }
        return;
    }

    /*
     * Deal with the transaction's result.
     */
    if (client_update_dnode_addr_storage(cs, cs->ctl_cur_txn) == -1) {
        return;
    }
    if (client_check_sata_device_ready(cs, cs->ctl_cur_txn) == -1) {
        return;
    }

    /* If the client asked us to read all the samples, we'll have
     * nsamples==0 in our bs_cfg. That's invalid, so we ask for the
     * value to put in it as part of setting up the storage.
     *
     * That value just came back, so update the next transaction,
     * where we set it.
     */
    struct raw_pkt_cmd *req_pkt = &cs->ctl_txns[cs->ctl_cur_txn].req_pkt;
    struct raw_cmd_res *res = ctxn_res(cs->ctl_txns + cs->ctl_cur_txn);
    if (res->r_type == RAW_RTYPE_SATA && res->r_addr == RAW_RADDR_SATA_W_IDX &&
        raw_req_is_read(req_pkt) && cpriv->bs_cfg->nsamples == 0) {
        struct control_txn *r_len_txn = cs->ctl_txns + cs->ctl_cur_txn + 1;
        struct raw_pkt_cmd *r_len_pkt = &r_len_txn->req_pkt;
        struct raw_cmd_req *r_len = raw_req(r_len_pkt);
        size_t sata_w_idx = (size_t)res->r_val;

        /* Sanity check everything, since this is so brittle. */
        /* FIXME what if nothing was written? We can't detect it yet. */
        assert(raw_req_is_write(r_len_pkt));
        assert(r_len->r_type == RAW_RTYPE_SATA);
        assert(r_len->r_addr == RAW_RADDR_SATA_R_LEN);
        assert(r_len->r_val == 0);
        assert(cpriv->bs_cfg->start_sample != -1);

        /* Don't let the client ask for samples that don't exist. */
        size_t start_sample = (size_t)cpriv->bs_cfg->start_sample;
        if (sata_w_idx < start_sample) {
            CLIENT_RES_ERR_C_VALUE(cs,
                                   "start_sample exceeds number of "
                                   "existing samples");
            return;
        }

        /* Set the number of packets to read; nsamples should really
         * be one larger, but we're covering for a potential
         * off-by-one in the HDL here. */
        size_t nsamples = sata_w_idx - start_sample;
        r_len->r_val = (uint32_t)nsamples;
        cpriv->bs_cfg->nsamples = nsamples;
    }

    /* If we just successfully enabled the UDP module, it's time to
     * tell the sample handler to expect incoming board samples, so
     * it'll be ready once the DAQ enable goes through. */
    /* NOTE: there's a race condition here. If there are packets still
     * on the wire or in a receive queue from a previous stream or
     * store command, the sample handler will consider them part of
     * this storage request and probably error out prematurely.
     *
     * This is the problem that TCP solves with TIME_WAIT.
     *
     * However:
     *
     * 1. it seems unlikely that this'd happen unless the event loop
     *    performance is really slow, and
     *
     * 2. we can recover from the error,
     *
     * so this doesn't seem worth trying to fix right now. */
    if (res->r_type == RAW_RTYPE_UDP && res->r_addr == RAW_RADDR_UDP_ENABLE &&
        raw_req_is_write(req_pkt) && res->r_val == 1) {
        if (sample_expect_bsamps(cs->smpl, cpriv->bs_cfg,
                                 client_sample_store_callback, cs) == -1) {
            CLIENT_RES_ERR_DAEMON(cs, "can't configure sample forwarding");
            return;
        } else if (!cpriv->bs_restarted) {
            cpriv->bs_expecting = 1;
            cpriv->bs_nwritten_cache = 0;
        } else {
            /* If we're restarting a transfer, then we should already
             * be expecting */
            assert(cpriv->bs_expecting);
        }
    }

    /*
     * Advance to the next transaction.
     *
     * If there aren't any more to come, the incoming packets are en
     * route. The sample callback handler we registered with
     * sample_expect_bsamps() will let us know when we need to send
     * the result to the client. So either way, there's nothing for us
     * to send, and we're done here.
     */
    client_start_next_txn(cs);
}

static void client_process_cmd_acquire(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    ControlCmdAcquire *acquire = cpriv->c_cmd->acquire;
    int enable;
    uint32_t exp_ck_h;
    uint32_t exp_ck_l;

    /* Sanity check our expectations with regards to sample storage. */
    assert(!cpriv->bs_cfg);
    assert(!cpriv->bs_expecting);
    assert(!cpriv->bs_restarted);

    /* Check that the command is well formed, setting optional fields
     * to default values. */
    if (!acquire->has_start_sample) {
        acquire->start_sample = 0;
    }
    if (!acquire) {
        CLIENT_RES_ERR_C_PROTO(cs, "missing acquire command");
        return;
    }
    if (!acquire->has_exp_cookie
            && acquire->has_enable
            && acquire->enable) {
        CLIENT_RES_ERR_C_PROTO(cs, "missing experiment cookie");
        return;
    }
    if (!acquire->has_enable) {
        CLIENT_RES_ERR_C_PROTO(cs, "missing enable");
        return;
    }
    if (acquire->start_sample % DAQ_MAGIC_MODULUS != 0) {
        CLIENT_RES_ERR_C_VALUE(cs, "start_sample is not divisible by "
                                   DAQ_MAGIC_MODULUS_STR);
        return;
    }
    if (UINT32_MAX - acquire->start_sample < DAQ_MAGIC_MODULUS) {
        CLIENT_RES_ERR_C_VALUE(cs, "start sample is too close to maximum; "
                                   "choose something smaller.");
        return;
    }

    /* Pull the fields we need out of the command. */
    exp_ck_h = (uint32_t)(acquire->exp_cookie >> 32);
    exp_ck_l = (uint32_t)(acquire->exp_cookie & 0xFFFFFFFF);
    enable = acquire->enable;

    const size_t max_ntxns = 15 + CLIENT_N_NET_TXNS;
    struct control_txn *txns = malloc(max_ntxns * sizeof(struct control_txn));
    size_t txno = 0;
    if (!txns) {
        CLIENT_RES_ERR_DAEMON_OOM(cs);
        return;
    }

    if (enable) {
        uint32_t start = acquire->start_sample;

        /* Our data sockets must know one another for streaming to
         * work. */
        ssize_t net = client_add_network_txns(cs, txns, max_ntxns);
        if (net == -1) {
            return;
        }
        txno = (size_t)net;
        /* Stop DAQ-UDP and DAQ-SATA output, then stop the DAQ module */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_UDP_ENABLE, 0);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_SATA_ENABLE, 0);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_ENABLE, 0);
        /* Stop SATA */
        client_sata_w(txns + txno++, RAW_RADDR_SATA_MODE, RAW_SATA_MODE_WAIT);
        /* Toggle DAQ-SATA FIFO flag reset bit */
        client_daq_w(txns + txno++,
                     RAW_RADDR_DAQ_SATA_FIFO_FL, RAW_DAQ_SATA_FIFO_FL_RST);
        client_daq_w(txns + txno++,
                     RAW_RADDR_DAQ_SATA_FIFO_FL, 0);
        /* Set experiment cookie */
        client_central_w(txns + txno++, RAW_RADDR_CENTRAL_EXP_CK_H, exp_ck_h);
        client_central_w(txns + txno++, RAW_RADDR_CENTRAL_EXP_CK_L, exp_ck_l);
        /* Set SATA start index, and follow recipe to sent DAQ start
         * index past start */
        client_sata_w(txns + txno++,
                      RAW_RADDR_SATA_WRITE_START_INDEX, start);
        client_daq_w(txns + txno++,
                     RAW_RADDR_DAQ_BSMP_START, start + DAQ_MAGIC_MODULUS);
        /* Configure SATA to write from DAQ */
        client_sata_w(txns + txno++, RAW_RADDR_SATA_MODE, RAW_SATA_MODE_WRITE);
        /* Enable DAQ acquisition, and DAQ-SATA weird/hack mode */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_ENABLE, 1);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_SATA_ENABLE, 3);
        /* Ensure SATA reports device ready. */
        client_sata_r(txns + txno++, RAW_RADDR_SATA_STATUS);
        /* Reset the board sample index to zero (this actually starts
         * the writes, so do it last) */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_BSMP_START, start);
    } else {
        /* Disable DAQ-SATA stream */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_SATA_ENABLE, 0);
        /* Disable SATA writes */
        client_sata_w(txns + txno++, RAW_RADDR_SATA_MODE, RAW_SATA_MODE_WAIT);
        /* Disable DAQ-UDP stream */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_UDP_ENABLE, 0);
        /* Disable UDP output */
        client_udp_w(txns + txno++, RAW_RADDR_UDP_ENABLE, 0);
        /* Disable DAQ */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_ENABLE, 0);
        /* Reset DAQ-UDP FIFO */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_FIFO_FLAGS, 1);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_FIFO_FLAGS, 0);
        /* Reset DAQ-SATA FIFO */
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_SATA_FIFO_FL, 1);
        client_daq_w(txns + txno++, RAW_RADDR_DAQ_SATA_FIFO_FL, 0);
    }
    client_start_txns(cs, txns, txno, max_ntxns);
}

static void client_process_res_acquire(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    ControlCmdAcquire *acquire = cpriv->c_cmd->acquire;

    if (client_ensure_txn_ok(cs, "ControlCmdAcquire") == -1) {
        return;
    }

    /*
     * If enabling acquisition:
     *
     * - deal with network transactions which pair the daemon/dnode
     *   data sockets.
     *
     * - check SATA device ready status
     */
    if (acquire->has_enable && acquire->enable) {
        size_t txn = cs->ctl_cur_txn;
        if (client_update_dnode_addr_storage(cs, txn) == -1 ||
            client_check_sata_device_ready(cs, txn) == -1) {
            return;
        }
    }

    if (!client_start_next_txn(cs)) {
        return;
    }
    client_send_success(cs);
}

static void client_process_cmd(struct control_session *cs)
{
    struct client_priv *cpriv = cs->cpriv;
    ControlCommand *cmd = cpriv->c_cmd;
    if (!cmd->has_type) {
        CLIENT_RES_ERR_C_PROTO(cs, "missing type field in command");
        return;
    }

    cmd_proc_fn proc;
    const char *type;

    switch (cmd->type) {
    case CONTROL_COMMAND__TYPE__REG_IO:
        proc = client_process_cmd_regio;
        type = "REG_IO";
        break;
    case CONTROL_COMMAND__TYPE__STREAM:
        proc = client_process_cmd_stream;
        type = "STREAM";
        break;
    case CONTROL_COMMAND__TYPE__STORE:
        proc = client_process_cmd_store;
        type = "STORE";
        break;
    case CONTROL_COMMAND__TYPE__ACQUIRE:
        proc = client_process_cmd_acquire;
        type = "ACQUIRE";
        break;
    default:
        CLIENT_RES_ERR_C_PROTO(cs, "unknown command type");
        return;
    }
    log_DEBUG("handling %s command (%d)", type, cmd->type);
    proc(cs);
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
    case CONTROL_COMMAND__TYPE__STORE:
        client_process_res_store(cs);
        break;
    case CONTROL_COMMAND__TYPE__ACQUIRE:
        client_process_res_acquire(cs);
        break;
    default:
        log_ERR("got result for unhandled command type; ignoring it");
        break;
    }
}

static void client_process_err(struct control_session *cs)
{
    if (!cs->cbev) {
        log_WARNING("swallowing dnode error packet; no one is listening");
    } else {
        CLIENT_RES_ERR_DNODE_ASYNC(cs);
    }
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
        /* There should be a command waiting for us */
        assert(cpriv(cs)->c_cmd);

        if (!cs->dbev) {     /* TODO fix this abstraction violation */
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
    .cs_partner_closed = client_partner_closed,
};

const struct control_ops *control_client_ops = &client_control_operations;
