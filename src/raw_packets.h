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

#ifndef _RAW_DATA_PACKETS_H_
#define _RAW_DATA_PACKETS_H_

#include <stdint.h>
#include <stddef.h>

#include "type_attrs.h"

/*********************************************************************
 * Packet data structures
 *
 * The main packet structure is struct raw_packet; see below.
 */

/* Board sample packet contents */

#define RAW_FLAG_BSAMP_IS_LIVE 0x01 /* "is_live" flag for ph.p_flags */
#define RAW_FLAG_BSAMP_IS_LAST 0x02 /* "is_last_sample" flag for ph.p_flags */

__packed
struct raw_msg_bsamp {
    uint32_t bs_idx;            /* Sample index */
    uint16_t bs_nchips;         /* Number of chips on this board */
    uint16_t bs_nlines;         /* Number of data samples per chip */
    uint16_t bs_samples[];      /* The samples themselves; this is in
                                 * chip-major order, and has
                                 * length=bs_nchips*bs_nlines. */
};

/* Request/response packet contents */

#define RAW_RTYPE_CHIP_CFG   0x00
#define RAW_RTYPE_CHIP_QUERY 0x01
#define RAW_RTYPE_SYS_CFG    0x02
#define RAW_RTYPE_SYS_QUERY  0x03
#define RAW_RTYPE_ACQ_START  0x04
#define RAW_RTYPE_ACQ_STOP   0x05
#define RAW_RTYPE_SAMP_READ  0x06

#define RAW_RADDR_NCHIPS     0x00
#define RAW_RADDR_NLINES     0x01

/* Request and response packets contain the same data, but we enforce
 * a type system distinction between them.
 *
 * ph: packet header
 * r_id: sequential request/response ID number; this can wrap
 * r_type: type of request/response being issued; see RAW_RTYPE_*
 * r_addr: notional "address" being written to or read from
 * r_val: value at r_addr to read or write
 */
#define _RAW_DATA_REQ_RES                       \
    uint16_t r_id;                              \
    uint8_t r_type;                             \
    uint8_t r_addr;                             \
    uint32_t r_val;
__packed
struct raw_msg_req { _RAW_DATA_REQ_RES };
__packed
struct raw_msg_res { _RAW_DATA_REQ_RES };
#undef _RAW_DATA_REQ_RES

/* Packet structure */

/* Current protocol version for .p_proto_vers. */
#define RAW_PROTO_VERS     0x00

/* Packet message types for .p_type.
 *
 * Note: don't use zero as a packet type value; that's reserved for
 * raw_packet_recv(). */
#define RAW_PKT_TYPE_BSAMP 0x01 /* Board sample */
#define RAW_PKT_TYPE_REQ   0x02 /* Request */
#define RAW_PKT_TYPE_RES   0x03 /* Response */
#define RAW_PKT_TYPE_ERR   0xFF /* Error */

/* Error flag for .p_flags, may occur anywhere. Each packet type may
 * define additional flags, as long as they don't conflict with this
 * one. */
#define RAW_FLAG_ERR       0x80

__packed
struct raw_packet {
    /* Packet header; this is common to packets of all types. */

    uint8_t _p_magic; /* Don't touch. */

    uint8_t p_proto_vers;       /* Protocol version */
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
 * protocol implementation details. They return 0 on success and -1 on
 * failure, with errno set. */

/* Send a data packet.
 *
 * This function modifies `packet'. You should treat the value in
 * `packet->p' as undefined after this call returns.
 *
 * `flags' are as with send(). */
int raw_packet_send(int sockfd, struct raw_packet *packet, int flags);

/* Receive a data packet.
 *
 * `*packtype' may be zero or a valid RAW_PKT_TYPE_* value. If
 * `*packtype' is zero, it will be modified to contain the received
 * packet header's p_type value.  If `*packtype' is nonzero, and the
 * packet read from the socket does not match its type, -1 is
 * returned, with errno set to EIO.
 *
 * Receiving a RAW_PKT_TYPE_BSAMP is a special case. In this case,
 * *packtype must be set appropriately, and the .bs_nchips and
 * .bs_nlines fields in packet->b.bsamp must be initialized properly.
 *
 * `flags' are as with recv(). */
int raw_packet_recv(int sockfd, struct raw_packet *packet, uint8_t *packtype,
                    int flags);

/*********************************************************************
 * Other packet routines
 */

/* Initialize a packet. Call this once before sending the packet
 * anywhere. */
void raw_packet_init(struct raw_packet *packet);

/* True iff `packet' signals an error condition. */
static inline int raw_packet_err(struct raw_packet *packet)
{
    return (packet->p_flags & RAW_FLAG_ERR ||
            packet->p_type == RAW_PKT_TYPE_ERR);
}

/* Number of samples in a raw_msg_bsamp. */
static inline size_t raw_bsamp_nsamps(struct raw_msg_bsamp *bsamp)
{
    return (size_t)bsamp->bs_nchips * (size_t)bsamp->bs_nlines;
}

/* Number of samples in a packet of type RAW_PKT_TYPE_BSAMP. */
static inline size_t raw_packet_nsamps(struct raw_packet *packet)
{
    return raw_bsamp_nsamps(&packet->p.bsamp);
}

/* Size of ->bs_samples in a raw_msg_bsamp. */
static inline size_t raw_bsamp_sampsize(struct raw_msg_bsamp *bsamp)
{
    return raw_bsamp_nsamps(bsamp) * sizeof(bsamp->bs_samples[0]);
}

/* Size of ->p.bsamp.bs_samples in a packet of type RAW_PKT_TYPE_BSAMP.  */
static inline size_t raw_packet_sampsize(struct raw_packet *packet)
{
    return raw_bsamp_sampsize(&packet->p.bsamp);
}

#endif  /* _RAW_DATA_PACKETS_H_ */
