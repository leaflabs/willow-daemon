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
#include <string.h>
#include <sys/types.h>

#include "type_attrs.h"

/*********************************************************************
 * Common packet header
 */

/* Message Types */
#define RAW_MTYPE_REQ   0x01 /* Request */
#define RAW_MTYPE_RES   0x02 /* Response */
#define RAW_MTYPE_ERR   0x7F /* Error */
#define RAW_MTYPE_BSUB  0x80 /* Board sub-sample */
#define RAW_MTYPE_BSMP  0x81 /* Board sample */

/* Error flag for raw_packet.p_flags. */
#define RAW_PFLAG_ERR   0x80

/* Packet header. */
struct raw_pkt_header {
    /* These are set by raw_packet_init(). */
    uint8_t _p_magic;
    uint8_t p_proto_vers;

    uint8_t p_mtype;            /* Message Type */
    uint8_t p_flags;            /* Status Flags */
};

/*********************************************************************
 * Command packets
 */

/*
 * Request/Response packet (RAW_MTYPE_REQ, RAW_MTYPE_RES) data
 */

/* Request and response packets contain the same data, but we provide
 * a type system distinction between them.
 *
 * r_id: sequential request/response ID number; this wraps
 * r_type: type of request/response being issued; see RAW_RTYPE_*
 * r_addr: register address being read from or written to
 * r_val: value read or written
 */
#define _RAW_C_REQ_RES                          \
    uint16_t r_id;                              \
    uint8_t r_type;                             \
    uint8_t r_addr;                             \
    uint32_t r_val;
struct raw_cmd_req { _RAW_C_REQ_RES };
struct raw_cmd_res { _RAW_C_REQ_RES };
#undef _RAW_C_REQ_RES

/* Request types */
#define RAW_RTYPE_ERR  0x00     /* Error */
#define RAW_RTYPE_TOP  0x01     /* Top-level module */
#define RAW_RTYPE_SATA 0x02     /* SATA storage */
#define RAW_RTYPE_DAQ  0x03     /* DAQ: e.g. front-end config, impedance */
#define RAW_RTYPE_UDP  0x04     /* UDP module config */
#define RAW_RTYPE_EXP  0x05     /* GPIO config for expansion pins */
#define RAW_RTYPE_NTYPES (RAW_RTYPE_EXP + 1)

/* I/O direction flag */
#define RAW_PFLAG_RIOD   (0x1)
#define RAW_PFLAG_RIOD_W (0U << 0)
#define RAW_PFLAG_RIOD_R (1U << 0)

/*
 * Per-r_type Registers
 */

/* RAW_RTYPE_ERR */
#define RAW_RADDR_ERR_ERR0 0x00 /* global error register 0 (r/w) */
#define RAW_RADDR_ERR_NREGS (RAW_RADDR_ERR_ERR0 + 1)

/* RAW_RTYPE_TOP */
#define RAW_RADDR_TOP_ERR         0x00 /* Module error flags */
#define RAW_RADDR_TOP_STATE       0x01 /* Module state */
#define RAW_RADDR_TOP_EXP_ID_H    0x02 /* Experiment ID, high word */
#define RAW_RADDR_TOP_EXP_ID_L    0x03 /* Experiment ID, low word */
#define RAW_RADDR_TOP_BSUB_CH_MIN 0x10 /* Subsample bitmask, ch.   0-  31 */
#define RAW_RADDR_TOP_BSUB_CH_MAX 0x2F /*               ..., ch. 992-1023 */
#define RAW_RADDR_TOP_NREGS (RAW_RADDR_TOP_BSUB_CH_MAX + 1)

/* RAW_RTYPE_SATA */
#define RAW_RADDR_SATA_ERR      0x00 /* Module error flags */
#define RAW_RADDR_SATA_STATE    0x01 /* Module state */
#define RAW_RADDR_SATA_DISK_ID  0x02 /* Disk identifier (TBD) */
#define RAW_RADDR_SATA_IO_PARAM 0x03 /* Disk I/O parameters (TBD) */
#define RAW_RADDR_SATA_R_IDX    0x04 /* Next read index */
#define RAW_RADDR_SATA_R_LEN    0x05 /* Read length */
#define RAW_RADDR_SATA_W_IDX    0x06 /* Last write index */
#define RAW_RADDR_SATA_NREGS (RAW_RADDR_SATA_W_IDX + 1)

/* RAW_RTYPE_DAQ */
#define RAW_RADDR_DAQ_ERR        0x00 /* Module error flags */
#define RAW_RADDR_DAQ_STATE      0x01 /* Module state */
#define RAW_RADDR_DAQ_BSMP_START 0x02 /* Desired board sample index */
#define RAW_RADDR_DAQ_BSMP_CURR  0x03 /* Current board sample index */
#define RAW_RADDR_DAQ_CHIP_ALIVE 0x04 /* Chip alive bitmask */
#define RAW_RADDR_DAQ_CHIP_CMD   0x05 /* CMD config */
#define RAW_RADDR_DAQ_NREGS (RAW_RADDR_DAQ_CHIP_CMD + 1)

/* RAW_RTYPE_UDP */
#define RAW_RADDR_UDP_ERR          0x00 /* Module error flags */
#define RAW_RADDR_UDP_STATE        0x01 /* Module state */
#define RAW_RADDR_UDP_SRC_MAC_H    0x02 /* Source MAC-48 address, high word */
#define RAW_RADDR_UDP_SRC_MAC_L    0x03 /* Source MAC-48 address, low word  */
#define RAW_RADDR_UDP_DST_MAC_H    0x04 /* Destination MAC-48, high word */
#define RAW_RADDR_UDP_DST_MAC_L    0x05 /* Destination MAC-48, low word */
#define RAW_RADDR_UDP_SRC_IP4      0x06 /* Source IPv4 address */
#define RAW_RADDR_UDP_DST_IP4      0x07 /* Destination IPv4 address */
#define RAW_RADDR_UDP_SRC_IP4_PORT 0x08 /* Source IPv4 port */
#define RAW_RADDR_UDP_DST_IP4_PORT 0x09 /* Destination IPv4 port */
#define RAW_RADDR_UDP_NREGS (RAW_RADDR_UDP_DST_IP4_PORT + 1)

/* RAW_RTYPE_EXP */
#define RAW_RADDR_EXP_ERR        0x00 /* Module error flags */
/* (No state machine for GPIO) */
#define RAW_RADDR_EXP_GPIOS      0x02 /* Available GPIO bitmask */
#define RAW_RADDR_EXP_GPIO_STATE 0x03 /* GPIO state */
#define RAW_RADDR_EXP_NREGS (RAW_RADDR_EXP_GPIO_STATE + 1)

/*
 * Error packet (RAW_MTYPE_ERR) data
 */

#define _RAW_CSIZE 8
struct raw_cmd_err {
    uint8_t pad_must_be_zero[_RAW_CSIZE];
};

/*
 * Command packet structure
 */

struct raw_pkt_cmd {
    struct raw_pkt_header ph;
    union {
        struct raw_cmd_req req;
        struct raw_cmd_res res;
        struct raw_cmd_err err;
    } p;
};

/*********************************************************************
 * Data packets
 */

/* Flags */
#define RAW_PFLAG_B_LIVE  0x01  /* streaming live recording */
#define RAW_PFLAG_B_LAST  0x02  /* no more packets to send */

typedef uint16_t raw_samp_t;

/*
 * Board subsample packet (RAW_MTYPE_BSUB) data
 */

struct raw_pkt_bsub {
    struct raw_pkt_header ph;
    uint32_t b_cookie_h;        /* experiment cookie high word */
    uint32_t b_cookie_l;        /* experiment cookie low word */
    uint32_t b_id;              /* board id */
    uint32_t b_sidx;            /* sample index */
    uint32_t b_nsamp;           /* number of samples */
    raw_samp_t b_samps[];       /* ... of length b_nsamp */
};

/*
 * Board sample packet (RAW_MTYPE_BSMP) data
 */

#define _RAW_BSMP_NSAMP (32*35) /* TODO (eventually) configurability */

struct raw_pkt_bsmp {
    struct raw_pkt_header ph;
    uint32_t b_cookie_h;        /* experiment cookie high word */
    uint32_t b_cookie_l;        /* experiment cookie low word */
    uint32_t b_id;              /* board id */
    uint32_t b_sidx;            /* sample index */
    uint32_t b_chip_live;       /* chip live status */
    raw_samp_t b_samps[_RAW_BSMP_NSAMP]; /* samples */
};

/*********************************************************************
 * Packet initialization
 */

/* Initialize a packet.
 *
 * packet: Pointer to a packet structure (i.e. a struct raw_pkt_cmd,
 *         struct raw_pkt_bsub, or struct raw_pkt_bsmp).
 * mtype: Type of packet to initialize in `packet' (RAW_MTYPE_*).
 * flags: Initial packet->ph.p_flags.
 */
void raw_packet_init(void *packet, uint8_t mtype, uint8_t flags);

/* Allocate and initialize a board subsample packet. Free it with free(). */
struct raw_pkt_bsub* raw_alloc_bsub(size_t nsamp);

/* Type-generic packet copy. */
void raw_pkt_copy(void *dst, const void *src);

/*********************************************************************
 * Access conveniences
 */

/* These assume offsetof(typeof(*pktp), ph) == 0, which we check in
 * the unit tests */
#define raw_proto_vers(pktp) (((struct raw_pkt_header*)(pktp))->p_proto_vers)
#define raw_mtype(pktp)      (((struct raw_pkt_header*)(pktp))->p_mtype)
#define raw_flags(pktp)      (((struct raw_pkt_header*)(pktp))->p_flags)
/* Is this an error packet? */
#define raw_pkt_is_err(pktp) ({                                           \
    struct raw_pkt_header *__pkt_ph = (struct raw_pkt_header*)pktp; \
    (raw_flags(__pkt_ph) & RAW_PFLAG_ERR ||                               \
     raw_mtype(__pkt_ph) == RAW_MTYPE_ERR); })

static inline struct raw_cmd_req* raw_req(struct raw_pkt_cmd *pkt)
{
    return &pkt->p.req;
}

static inline struct raw_cmd_res* raw_res(struct raw_pkt_cmd *pkt)
{
    return &pkt->p.res;
}

static inline uint16_t raw_r_id(const struct raw_pkt_cmd *pkt)
{
    return raw_req((struct raw_pkt_cmd*)pkt)->r_id;
}

static inline uint8_t raw_r_type(const struct raw_pkt_cmd *pkt)
{
    return raw_req((struct raw_pkt_cmd*)pkt)->r_type;
}

static inline uint8_t raw_r_addr(const struct raw_pkt_cmd *pkt)
{
    return raw_req((struct raw_pkt_cmd*)pkt)->r_addr;
}

static inline uint32_t raw_r_val(const struct raw_pkt_cmd *pkt)
{
    return raw_req((struct raw_pkt_cmd*)pkt)->r_val;
}

/* Full uint64_t experiment cookie */
#define raw_exp_cookie(pktp) ({                                 \
    __typeof__(pktp) __pktp = pktp;                             \
    ((uint64_t)__pktp->b_cookie_h << 32) | (uint64_t)__pktp->b_cookie_l; })

/* Number of samples in a board sample (for future-proofing). */
static inline size_t raw_bsmp_nsamp(__unused const struct raw_pkt_bsmp *bsmp)
{
    return _RAW_BSMP_NSAMP;
}

/* Size of samples array in a board sample. */
static inline size_t raw_bsmp_sampsize(const struct raw_pkt_bsmp *bsmp)
{
    return raw_bsmp_nsamp(bsmp) * sizeof(raw_samp_t);
}

/* Overall size of a board sample (for future-proofing). */
static inline size_t raw_bsmp_size(__unused const struct raw_pkt_bsmp *bsmp)
{
    return sizeof(struct raw_pkt_bsmp);
}

/* Number of samples in a board subsample. */
static inline size_t raw_bsub_nsamp(const struct raw_pkt_bsub *bsub)
{
    return bsub->b_nsamp;
}

/* Size of samples array in a board sample. */
static inline size_t raw_bsub_sampsize(const struct raw_pkt_bsub *bsub)
{
    return raw_bsub_nsamp(bsub) * sizeof(raw_samp_t);
}

/* Overall size of a board subsample. */
static inline size_t raw_bsub_size(const struct raw_pkt_bsub *bsub)
{
    return sizeof(struct raw_pkt_bsub) + raw_bsub_sampsize(bsub);
}

/* Type-generic packet size
 *
 * pkt: pointer to struct raw_pkt_cmd, raw_pkt_bsub, or
 *      raw_pkt_bsmp. */
size_t raw_pkt_size(const void *pkt);

/*********************************************************************
 * Packet send/recv primitives.
 *
 * These convenience routines handle byte order swapping and some
 * protocol implementation details. They return a positive number on
 * success and -1 on failure, with errno set.
 */

/* Send a command packet.
 *
 * This function modifies `packet'. You should treat the value in
 * `packet->p' as undefined after this call returns.
 *
 * `flags' are as with send(). */
ssize_t raw_cmd_send(int sockfd, struct raw_pkt_cmd *pkt, int flags);

/* Receive a data packet.
 *
 * `packet->p_type' may be either zero or a valid RAW_MTYPE_*
 * value. If nonzero, and the packet read from the socket does not
 * match its type, -1 is returned, with errno set to EIO.
 *
 * `flags' are as with recv(). */
ssize_t raw_cmd_recv(int sockfd, struct raw_pkt_cmd *pkt, int flags);

/* Like raw_cmd_send(), but for RAW_MTYPE_BSUB packets.
 *
 * This is mostly for debugging. */
ssize_t raw_bsub_send(int sockfd, struct raw_pkt_bsub *bsub, int flags);

/* Like raw_cmd_recv(), but for RAW_MTYPE_BSUB packets.
 *
 * `bsub' must be properly initalized to reflect how many samples you
 * expect to receive.
 */
ssize_t raw_bsub_recv(int sockfd, struct raw_pkt_bsub *bsub, int flags);

/* Like raw_cmd_send(), but for RAW_MTYPE_BSMP packets.
 *
 * This is mostly for debugging. */
ssize_t raw_bsmp_send(int sockfd, struct raw_pkt_bsmp *bsmp, int flags);

/* Like raw_cmd_recv(), but for RAW_MTYPE_BSMP packets. */
ssize_t raw_bsmp_recv(int sockfd, struct raw_pkt_bsmp *bsmp, int flags);

#endif
