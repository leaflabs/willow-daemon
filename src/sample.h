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
 * @file src/sample.h
 *
 * libevent-aware data socket handling.
 */

#ifndef _SRC_SAMPLE_H_
#define _SRC_SAMPLE_H_

#include <stdint.h>
#include <sys/socket.h>

struct sample_session;
struct event_base;

/**
 * Create a new sample packet handler.
 *
 * The handler will start listening on the given interface/port
 * combination, but will ignore any packets until you configure it to
 * do something with them. You can forward board subsample packets
 * with sample_cfg_subsamples(). You can save board sample packets to
 * disk with sample_expect_bsamps().
 *
 * @param base Event loop base
 * @param iface Interface number (see <net/if.h>) for sample data socket.
 * @param port Port to bind to on iface.
 * @return New sample handler on success, NULL on failure.
 */
struct sample_session* sample_new(struct event_base *base,
                                  unsigned iface,
                                  uint16_t port);
/**
 * Free resources allocated by a sample packet handler.
 *
 * You must call this from the thread controlling smpl's event loop.
 */
void sample_free(struct sample_session *smpl);

/** Get daemon data socket's address. */
int sample_get_saddr(struct sample_session *smpl,
                     int af,
                     struct sockaddr *addr,
                     socklen_t *addrlen);
/** Get daemon data socket interface's MAC48 address. */
int sample_get_mac48(struct sample_session *smpl, uint8_t mac48[6]);

enum sample_addr {
    SAMPLE_ADDR_CLIENT,
    SAMPLE_ADDR_DNODE,
};
int sample_get_addr(struct sample_session *smpl,
                    struct sockaddr *addr,
                    socklen_t *addrlen,
                    enum sample_addr what);
int sample_set_addr(struct sample_session *smpl,
                    struct sockaddr *addr,
                    enum sample_addr what);

/** Sample forwarding configuration */
enum sample_forward {
    SAMPLE_FWD_NOTHING = 0,     /**< Forward no packets */
    SAMPLE_FWD_BSMP = 1,        /**< Forward board subsamples as protobuf */
    SAMPLE_FWD_BSUB = 2,        /**< Forward board samples as protobuf */
    SAMPLE_FWD_BSMP_RAW = 4,    /**< Forward board samples as raw packets */
    SAMPLE_FWD_BSUB_RAW = 8,    /**< Forward board subsamples as raw packets */
};

/**
 * Enable or disable live data forwarding.
 *
 * If enabling, you must previously have configured client and data
 * node addresses with sample_set_addr().
 *
 * @param smpl Sample handler
 * @param what What to forward; use SAMPLE_NOTHING to disable.
 */
int sample_cfg_forwarding(struct sample_session *smpl,
                          enum sample_forward what);

struct ch_storage;

/**
 * Configuration structure for a future board sample transfer
 */
struct sample_bsamp_cfg {
    size_t nsamples;            /**< Number of samples to expect */
    /** Index of first sample to expect. This currently must be positive. */
    ssize_t start_sample;
    /**
     * Channel storage handler.
     *
     * This must be open and ready for ch_storage_write() and
     * ch_storage_datasync() calls. */
    struct ch_storage *chns;
};

#define SAMPLE_BS_DONE 0x1      /**< Finished writing all samples */
#define SAMPLE_BS_ERR 0x2       /**< Generic error */
#define SAMPLE_BS_PKTDROP 0x4   /**< Dropped a sample packet */
#define SAMPLE_BS_TIMEOUT 0x8   /**< Timed out while waiting for packets */

/**
 * Callback function for board sample storage configuration.
 *
 * @param events Logical OR of SAMPLE_BS_*.
 * @param nwritten The number of board samples written (though not
 *                 necessarily synced) to disk before the event that
 *                 caused the callback to fire. No additional board
 *                 samples will be written.
 * @param arg Argument from sample_expect_board_samples()
 * @see sample_expect_board_samples(), sample_reject_board_samples() */
typedef void (*sample_bsamp_cb)(short events, size_t nwritten, void *arg);

/**
 * Start accepting board sample packets, and save them to disk.
 *
 * The data node address must have been previously configured using
 * sample_set_addr().
 *
 * To halt board sample reading, use sample_reject_bsamps().
 *
 * You can't call this function from a callback you've passed to
 * it. (I.e., you can't call this function within the function pointed
 * to by "cb".)
 *
 * @param smpl Sample handler
 * @param cfg Sample retrieval configuration
 * @param cb Event/error callback function; this must not be NULL. It
 *           will be called from smpl's event base's thread.
 * @param arg  Passed to "cb".
 * @return 0 on success, -1 on failure.
 * @see sample_set_addr(), sample_new(), sample_reject_bsamps()
 */
int sample_expect_bsamps(struct sample_session *smpl,
                         struct sample_bsamp_cfg *cfg,
                         sample_bsamp_cb cb, void *arg);

/**
 * Stop accepting board sample packets.
 *
 * It's an error to call this function without having called
 * sample_expect_bsamps() first, or if the callback specified in the
 * sample_expect_bsamps() call has already been called.
 *
 * This function may block.
 *
 * @param smpl Sample handler.
 * @return Number of board samples written and synced to disk on
 *         success, -1 on failure.
 * @see sample_expect_bsamps();
 */
ssize_t sample_reject_bsamps(struct sample_session *smpl);

#endif
