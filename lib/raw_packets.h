/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

/* XXX this is just a sketch; don't take it too seriously. [mbolivar] */

/**
 * @file raw_data_packets.h
 *
 * @brief Utilities for talking directly to data nodes.
 *
 * This file is used to speak the data node (i.e. FPGA board) network
 * protocol. It is low-level and can change without notice. Don't
 * confuse it with the protobuf-based network protocol spoken to other
 * downstream data sinks, which is high-level and will be stable
 * eventually.
 */

#ifndef _LIB_RAW_PACKETS_H_
#define _LIB_RAW_PACKETS_H_

#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include "type_attrs.h"

/*********************************************************************
 * Packet data structures
 *
 * The main packet structure is struct raw_packet; see below.
 */

/* Error flag for raw_packet.p_flags, may occur anywhere. Each packet
 * type may define additional flags, as long as they don't conflict
 * with this one. */
#define RAW_FLAG_ERR       0x80

/* Board sample packet contents */

/* Flags for packet.p_flags */
#define RAW_FLAG_BSAMP_IS_LIVE 0x01 /* streaming live recording */
#define RAW_FLAG_BSAMP_IS_LAST 0x02 /* no more packets to send */
#define RAW_FLAG_BSAMP_ESIZE (RAW_FLAG_ERR | 0x04) /* requested sample
                                                      doesn't exist */

typedef uint16_t raw_samp_t;

__packed
struct raw_msg_bsamp {
    uint32_t   bs_idx;          /* Sample index */
    uint16_t   bs_nchips;       /* Number of chips on this board */
    uint16_t   bs_nlines;       /* Number of data samples per chip */
    raw_samp_t bs_samples[];    /* The samples themselves; this is in
                                 * chip-major order, and has length =
                                 * bs_nchips*bs_nlines. */
};

/* Request/response packet contents */

#define RAW_RTYPE_CHIP_CFG   0x00 /* configure a chip */
#define RAW_RTYPE_CHIP_QUERY 0x01 /* request a chip config */
#define RAW_RTYPE_SYS_CFG    0x02 /* configure the system */
#define RAW_RTYPE_SYS_QUERY  0x03 /* request system configuration */
#define RAW_RTYPE_ACQ_START  0x04 /* start acquisition */
#define RAW_RTYPE_ACQ_STOP   0x05 /* stop acquisition */
#define RAW_RTYPE_SAMP_READ  0x06 /* read a sample */

#define RAW_RADDR_SYS_NCHIPS 0x00
#define RAW_RADDR_SYS_NLINES 0x01

/* Request and response packets contain the same data, but we enforce
 * a type system distinction between them.
 *
 * Usually, these work like this:
 *
 * ph: packet header
 * r_id: sequential request/response ID number; this can wrap
 * r_type: type of request/response being issued; see RAW_RTYPE_*
 * r_addr: notional "address" being written to or read from
 * r_val: value at r_addr to read or write
 *
 * In case of .r_type=RAW_RTYPE_SAMP_READ, the following fields have
 * alternate meanings:
 *
 * r_addr: Number of board samples to read; must be > 0
 * r_val: Starting board sample to read from
 *
 * If more board sample packets are requested than are available, it's
 * not an error; the node just sends a packet with
 * RAW_FLAG_BSAMP_IS_LAST after receiving the number that were
 * available.
 *
 * If the starting board sample packet exceeds the number available,
 * an error is returned.
 */
#define _RAW_DATA_REQ_RES                       \
    uint16_t r_id;                              \
    uint8_t r_type;                             \
    uint8_t r_addr;                             \
    uint32_t r_val;
struct raw_msg_req { _RAW_DATA_REQ_RES };
struct raw_msg_res { _RAW_DATA_REQ_RES };
#undef _RAW_DATA_REQ_RES

/* Packet structure */

/* Packet message types for .p_type.
 *
 * Note: don't use zero as a packet type value; that's reserved for
 * raw_packet_recv(). */
#define RAW_PKT_TYPE_BSAMP 0x01 /* Board sample */
#define RAW_PKT_TYPE_REQ   0x02 /* Request */
#define RAW_PKT_TYPE_RES   0x03 /* Response */
#define RAW_PKT_TYPE_ERR   0xFF /* Error */

struct raw_packet {
    /* Packet header; this is common to packets of all types. */

    /* These are set by raw_packet_init(). You should probably leave
     * them alone. */
    uint8_t _p_magic;
    uint8_t _p_proto_vers;

    uint8_t p_type;             /* Packet type */
    uint8_t p_flags;            /* Extra flags */

    /* (Optional) packet contents
     *
     * In case of a plain error packet (.p_type == RAW_PKT_TYPE_ERR),
     * leave this uninitialized. */

    union {
        struct raw_msg_bsamp bsamp;
        struct raw_msg_req req;
        struct raw_msg_res res;
    } p;
};

/*********************************************************************
 * Packet send/recv primitives.
 *
 * These convenience routines handle byte order swapping and some
 * protocol implementation details. They return a positive number on
 * success and -1 on failure, with errno set.
 *
 * Note that due to protocol implementation details, the return values
 * of these functions might differ from what you'd expect out of
 * ordinary send()/recv().
 */

/* Send a data packet.
 *
 * This function modifies `packet'. You should treat the value in
 * `packet->p' as undefined after this call returns.
 *
 * `flags' are as with send(). */
ssize_t raw_packet_send(int sockfd, struct raw_packet *packet, int flags);

/* TODO: remove packtype field and just read from packet->p_type;
 * packtype is annoying to think about. */

/* Receive a data packet.
 *
 * `*packtype' may be a NULL pointer, or point to zero or a valid
 * RAW_PKT_TYPE_* value. If `*packtype' is zero, it will be modified
 * to contain the received packet header's p_type value.  If
 * `*packtype' is nonzero, and the packet read from the socket does
 * not match its type, -1 is returned, with errno set to EIO.
 *
 * Receiving a RAW_PKT_TYPE_BSAMP is a special case. In this case,
 * *packtype must be set appropriately, and the .bs_nchips and
 * .bs_nlines fields in packet->b.bsamp must be initialized properly.
 *
 * `flags' are as with recv(). */
ssize_t raw_packet_recv(int sockfd, struct raw_packet *packet,
                        uint8_t *packtype, int flags);

/*********************************************************************
 * Other packet routines and help
 */

/* For defining non-board sample packets, to reserve enough space in .p */
#define RAW_REQ_INIT { .p = { .req = { .r_id = 0 } }}
#define RAW_RES_INIT { .p = { .res = { .r_id = 0 } }}
#define RAW_ERR_INIT { .p_type = RAW_PKT_TYPE_ERR, .p_flags = RAW_FLAG_ERR }

/* Initialize a packet. Call this once before sending the packet
 * anywhere. */
void raw_packet_init(struct raw_packet *packet,
                     uint8_t type, uint8_t flags);

/* Create a board sample packet.
 *
 * Allocates a struct raw_packet of sufficient size to store `nchips *
 * nlines' samples. It initializes its ->p.bsamp.bs_nchips and
 * ->p.bsamp.bs_nlines fields to match nchips and nlines, and its
 * ->p_type field to RAW_PKT_TYPE_BSAMP. It additionally calls
 * raw_packet_init() on the result.
 *
 * Returns NULL when out of memory. */
struct raw_packet* raw_packet_create_bsamp(uint16_t nchips, uint16_t nlines);

/* True iff `packet' signals an error condition. */
static inline int raw_packet_err(const struct raw_packet *packet)
{
    return (packet->p_flags & RAW_FLAG_ERR ||
            packet->p_type == RAW_PKT_TYPE_ERR);
}

/* Number of samples in a raw_msg_bsamp. */
static inline size_t raw_bsamp_nsamps(const struct raw_msg_bsamp *bsamp)
{
    return (size_t)bsamp->bs_nchips * (size_t)bsamp->bs_nlines;
}

/* Number of samples in a packet of type RAW_PKT_TYPE_BSAMP. */
static inline size_t raw_packet_nsamps(const struct raw_packet *packet)
{
    return raw_bsamp_nsamps(&packet->p.bsamp);
}

/* Size of ->bs_samples in a raw_msg_bsamp. */
static inline size_t raw_bsamp_sampsize(const struct raw_msg_bsamp *bsamp)
{
    return raw_bsamp_nsamps(bsamp) * sizeof(bsamp->bs_samples[0]);
}

/* Size of ->p.bsamp.bs_samples in a packet of type RAW_PKT_TYPE_BSAMP.  */
static inline size_t raw_packet_sampsize(const struct raw_packet *packet)
{
    return raw_bsamp_sampsize(&packet->p.bsamp);
}

/* TODO bounds-checking */
void raw_packet_copy(struct raw_packet *restrict dst,
                     const struct raw_packet *restrict src);

/* Request/response ID number */
static inline uint16_t raw_r_id(const struct raw_packet *packet) {
    assert(packet->p_type == RAW_PKT_TYPE_REQ ||
           packet->p_type == RAW_PKT_TYPE_RES);
    return packet->p.req.r_id;
}

/* Request/response type */
static inline uint8_t raw_r_type(const struct raw_packet *packet) {
    assert(packet->p_type == RAW_PKT_TYPE_REQ ||
           packet->p_type == RAW_PKT_TYPE_RES);
    return packet->p.req.r_type;
}

/* Request/response address */
static inline uint8_t raw_r_addr(const struct raw_packet *packet) {
    assert(packet->p_type == RAW_PKT_TYPE_REQ ||
           packet->p_type == RAW_PKT_TYPE_RES);
    return packet->p.res.r_addr;
}

/* Request/response value */
static inline uint32_t raw_r_val(const struct raw_packet *packet) {
    assert(packet->p_type == RAW_PKT_TYPE_REQ ||
           packet->p_type == RAW_PKT_TYPE_RES);
    return packet->p.res.r_val;
}

#endif
