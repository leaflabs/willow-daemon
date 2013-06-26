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

/** @name Message Types */
///@{
#define RAW_MTYPE_REQ   0x01 /* Request */
#define RAW_MTYPE_RES   0x02 /* Response */
#define RAW_MTYPE_ERR   0x7F /* Error */
#define RAW_MTYPE_BSUB  0x80 /* Board sub-sample */
#define RAW_MTYPE_BSMP  0x81 /* Board sample */
///@}

/* Error flag for raw_packet.p_flags. */
#define RAW_PFLAG_ERR   0x80

/** @name Packet header */
///@{
#define RAW_PKT_HEADER_MAGIC      0x5A
#define RAW_PKT_HEADER_PROTO_VERS 0x00
///@}

/** Common packet header. */
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
/** Request packet message data */
struct raw_cmd_req { _RAW_C_REQ_RES };
/** Response packet message data */
struct raw_cmd_res { _RAW_C_REQ_RES };
#undef _RAW_C_REQ_RES

/** @name Request Types  */
///@{
#define RAW_RTYPE_ERR     0x00  /* Error */
#define RAW_RTYPE_CENTRAL 0x01  /* Central module */
#define RAW_RTYPE_SATA    0x02  /* SATA storage */
#define RAW_RTYPE_DAQ     0x03  /* DAQ: e.g. front-end config, impedance */
#define RAW_RTYPE_UDP     0x04  /* UDP module config */
#define RAW_RTYPE_GPIO    0x05  /* GPIO config for expansion pins */
#define RAW_RTYPE_NTYPES  (RAW_RTYPE_GPIO + 1)
///@}

/* I/O direction flag */
#define RAW_PFLAG_RIOD   (0x1)
#define RAW_PFLAG_RIOD_W (1U << 0)
#define RAW_PFLAG_RIOD_R (0U << 0)

/*
 * Per-r_type registers and values
 */

/**
 * @name Per-rtype Registers
 *
 * Names are prefixed by the request type the register pertains to. */
///@{
/* RAW_RTYPE_ERR */
#define RAW_RADDR_ERR_ERR0 0x00 /* global error register 0 (r/w) */
#define RAW_RADDR_ERR_NREGS (RAW_RADDR_ERR_ERR0 + 1)
/* RAW_RTYPE_CENTRAL */
#define RAW_RADDR_CENTRAL_ERR         0x00 /* Module error flags */
#define RAW_RADDR_CENTRAL_STATE       0x01 /* Module state */
#define RAW_RADDR_CENTRAL_EXP_CK_H    0x02 /* Experiment cookie, high word */
#define RAW_RADDR_CENTRAL_EXP_CK_L    0x03 /* Experiment cookie, low word */
#define RAW_RADDR_CENTRAL_NREGS (RAW_RADDR_CENTRAL_EXP_CK_L + 1)
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
#define RAW_RADDR_DAQ_ERR          0x00 /* Module error flags */
#define RAW_RADDR_DAQ_STATE        0x01 /* Module state */
#define RAW_RADDR_DAQ_BSMP_START   0x02 /* Desired board sample index */
#define RAW_RADDR_DAQ_BSMP_CURR    0x03 /* Current board sample index */
#define RAW_RADDR_DAQ_CHIP_ALIVE   0x04 /* Chip alive bitmask */
#define RAW_RADDR_DAQ_CHIP_CMD     0x05 /* CMD config */
#define RAW_RADDR_DAQ_CHIP_SYNCH   0x06 /* Synchronous sampling mode (TBD) */
#define RAW_RADDR_DAQ_FIFO_COUNT   0x07 /* FIFO read count ("byte in FIFO") */
#define RAW_RADDR_DAQ_FIFO_FLAGS   0x08 /* TBD */
#define RAW_RADDR_DAQ_UDP_ENABLE   0x09 /* UDP Output Enable */
#define RAW_RADDR_DAQ_UDP_MODE     0x0A /* UDP Output Mode */
#define RAW_RADDR_DAQ_SATA_ENABLE  0x0B /* DAQ SATA Output Enable */
#define RAW_RADDR_DAQ_BSUB0_CFG    0x80 /* subsample #0 configuration */
    /* ... */
#define RAW_RADDR_DAQ_BSUB31_CFG  0x80 /* subsample #31 configuration */
#define RAW_RADDR_DAQ_NREGS (RAW_RADDR_DAQ_BSUB31_CFG + 1)
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
#define RAW_RADDR_UDP_PKT_TX_COUNT 0x0A /* Packet TX count */
#define RAW_RADDR_UDP_ETH_PKT_LEN  0x0B /* Ethernet packet length */
#define RAW_RADDR_UDP_PAYLOAD_LEN  0x0C /* Payload length */
#define RAW_RADDR_UDP_MODE         0x0D /* UDP Module Mode */
#define RAW_RADDR_UDP_GIGE_STATUS  0x0E /* GigE Status */
#define RAW_RADDR_UDP_NREGS (RAW_RADDR_UDP_GIGE_STATUS + 1)
/* RAW_RTYPE_GPIO */
#define RAW_RADDR_GPIO_ERR   0x00 /* Module error flags */
/* (No state machine for GPIO) */
#define RAW_RADDR_GPIO_READ  0x02 /* GPIO read mask */
#define RAW_RADDR_GPIO_WRITE 0x03 /* GPIO write mask */
#define RAW_RADDR_GPIO_STATE 0x04 /* GPIO state */
#define RAW_RADDR_GPIO_NREGS (RAW_RADDR_GPIO_STATE + 1)
///@}

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

/**
 * @name Packet static initializer macros
 *
 * If you use one of these on a request or response, you still need to
 * initialize .r_type, .r_addr, and .r_val later, somehow.
 *
 * @see raw_req_init(), raw_res_init()
 */
///@{
/** DO NOT USE */
#define _RAW_PKT_HEADER_INITIALIZER(mtype)              \
    { ._p_magic = RAW_PKT_HEADER_MAGIC,                 \
      .p_proto_vers = RAW_PKT_HEADER_PROTO_VERS,        \
      .p_mtype = (mtype),                               \
      .p_flags = 0,                                     \
    }

/** Initializer macro for a raw_pkt_cmd of request mtype, RAW_MTYPE_REQ. */
#define RAW_PKT_REQ_INITIALIZER                                 \
    { .ph = _RAW_PKT_HEADER_INITIALIZER(RAW_MTYPE_REQ),         \
      .p = { .req = { .r_id = 0, .r_type = 0xFF,                \
                      .r_addr = 0xFF, .r_val = 0xdeadbeef } },  \
    }
/** Initializer macro for a raw_pkt_cmd of response mtype, RAW_MTYPE_RES. */
#define RAW_PKT_RES_INITIALIZER                             \
    { .ph = _RAW_PKT_HEADER_INITIALIZER(RAW_MTYPE_RES),     \
      .p = { .res = { .r_id = 0, .r_type = 0xFF,            \
                      .r_addr = 0xFF, .r_val = 0xdeadbeef } \
    }
/** Initializer macro for a raw_pkt_cmd of error mtype, RAW_MTYPE_ERR. */
#define RAW_PKT_ERR_INITIALIZER                                         \
    { .ph = _RAW_PKT_HEADER_INITIALIZER(RAW_MTYPE_ERR),                 \
      .p = { .err = { .pad_must_be_zero = { [_RAW_CSIZE - 1] = 0 } } }, \
    }
///@}

/*********************************************************************
 * Data packets
 */

/** @name Data packet types */

///@{

/* Flags */
#define RAW_PFLAG_B_LIVE  0x01  /* streaming live recording */
#define RAW_PFLAG_B_LAST  0x02  /* no more packets to send */

typedef uint16_t raw_samp_t;

/*
 * Board subsample packet (RAW_MTYPE_BSUB) data
 */

struct raw_bsub_cfg {
    uint8_t bs_chip;               /* chip index */
    uint8_t bs_chan;               /* channel index */
};

#define RAW_BSUB_NSAMP 32

/** Board subsample wire format struct */
struct raw_pkt_bsub {
    struct raw_pkt_header ph;   /**< Packet header */
    uint32_t b_cookie_h;        /**< experiment cookie high word */
    uint32_t b_cookie_l;        /**< experiment cookie low word */
    uint32_t b_id;              /**< board id */
    uint32_t b_sidx;            /**< sample index */
    uint32_t b_chip_live;       /**< live chip mask */

    struct raw_bsub_cfg b_cfg[RAW_BSUB_NSAMP]; /**< chip/channel config */
    raw_samp_t b_samps[RAW_BSUB_NSAMP]; /**< the samples themselves */

    uint16_t b_gpio;            /**< GPIO data */
    uint8_t b_dac_cfg;          /**< DAC enable/channel */
    uint8_t b_dac;              /**< DAC value */
};

/*
 * Board sample packet (RAW_MTYPE_BSMP) data
 */

#define _RAW_BSMP_NSAMP (32*35) /* TODO (eventually) configurability */

/** Board sample wire format struct */
struct raw_pkt_bsmp {
    struct raw_pkt_header ph;   /**< Packet header */
    uint32_t b_cookie_h;        /**< experiment cookie high word */
    uint32_t b_cookie_l;        /**< experiment cookie low word */
    uint32_t b_id;              /**< board id */
    uint32_t b_sidx;            /**< sample index */
    uint32_t b_chip_live;       /**< chip live status */
    raw_samp_t b_samps[_RAW_BSMP_NSAMP]; /**< samples */
};

///@}

/*********************************************************************
 * Packet initialization
 */

/**
 * Initialize a packet.
 *
 * @param packet Pointer to a packet structure (i.e. a struct raw_pkt_cmd,
 *               struct raw_pkt_bsub, or struct raw_pkt_bsmp).
 * @param mtype  Type of packet to initialize in `packet' (RAW_MTYPE_*).
 * @param flags  Initial packet->ph.p_flags.
 */
void raw_packet_init(void *packet, uint8_t mtype, uint8_t flags);

/** Initialize a request packet */
void raw_req_init(struct raw_pkt_cmd *req, uint8_t flags, uint16_t r_id,
                  uint8_t r_type, uint8_t r_addr, uint32_t r_val);

/** Initialize a response packet */
void raw_res_init(struct raw_pkt_cmd *res, uint8_t flags, uint16_t r_id,
                  uint8_t r_type, uint8_t r_addr, uint32_t r_val);

/** Type-generic packet copy. */
void raw_pkt_copy(void *dst, const void *src);

/*********************************************************************
 * Access conveniences
 */

/* These assume offsetof(typeof(*pktp), ph) == 0, which we check in
 * the unit tests */

/** @name Packet header accessors */

///@{

/** @brief Packet protocol version
 * pktp may point to a struct raw_pkt_cmd, raw_pkt_bsub, or raw_pkt_bsmp. */
#define raw_proto_vers(pktp) (((struct raw_pkt_header*)(pktp))->p_proto_vers)

/** @brief Packet message type.
 * pktp may point to a struct raw_pkt_cmd, raw_pkt_bsub, or raw_pkt_bsmp. */
#define raw_mtype(pktp)      (((struct raw_pkt_header*)(pktp))->p_mtype)

/** @brief Packet flags.
 * pktp may point to a struct raw_pkt_cmd, raw_pkt_bsub, or raw_pkt_bsmp. */
#define raw_pflags(pktp)     (((struct raw_pkt_header*)(pktp))->p_flags)

/** @brief Is this an error packet?
 * pktp may point to a struct raw_pkt_cmd, raw_pkt_bsub, or raw_pkt_bsmp. */
#define raw_pkt_is_err(pktp) ({                                     \
    struct raw_pkt_header *__pkt_ph = (struct raw_pkt_header*)pktp; \
    (raw_pflags(__pkt_ph) & RAW_PFLAG_ERR ||                        \
     raw_mtype(__pkt_ph) == RAW_MTYPE_ERR); })

/** Clear all packet flags in `flags'. */
static inline void raw_clear_flags(struct raw_pkt_cmd *pkt, uint8_t flags)
{
    pkt->ph.p_flags &= ~flags;
}

/** Set all packet flags in `flags'. */
static inline void raw_set_flags(struct raw_pkt_cmd *pkt, uint8_t flags)
{
    pkt->ph.p_flags |= flags;
}

///@}

/** @name Requests/responses */

///@{

/** Test if a request packet is a write */
static inline int raw_req_is_write(struct raw_pkt_cmd *pkt)
{
    return (raw_pflags(pkt) & RAW_PFLAG_RIOD) == RAW_PFLAG_RIOD_W;
}

/** Test if a request packet is a read */
static inline int raw_req_is_read(struct raw_pkt_cmd *pkt)
{
    return (raw_pflags(pkt) & RAW_PFLAG_RIOD) == RAW_PFLAG_RIOD_R;
}

/** Get pointer to request message data from a request packet */
static inline struct raw_cmd_req* raw_req(struct raw_pkt_cmd *pkt)
{
    return &pkt->p.req;
}

/** Get pointer to response message data from a response packet */
static inline struct raw_cmd_res* raw_res(struct raw_pkt_cmd *pkt)
{
    return &pkt->p.res;
}

/** Get a request/response packet's r_id value */
static inline uint16_t raw_r_id(const struct raw_pkt_cmd *pkt)
{
    return raw_req((struct raw_pkt_cmd*)pkt)->r_id;
}

/** Get a request/response packet's r_type value */
static inline uint8_t raw_r_type(const struct raw_pkt_cmd *pkt)
{
    return raw_req((struct raw_pkt_cmd*)pkt)->r_type;
}

/** Get a request/response packet's r_addr value */
static inline uint8_t raw_r_addr(const struct raw_pkt_cmd *pkt)
{
    return raw_req((struct raw_pkt_cmd*)pkt)->r_addr;
}

/** Get a request/response packet's r_val value */
static inline uint32_t raw_r_val(const struct raw_pkt_cmd *pkt)
{
    return raw_req((struct raw_pkt_cmd*)pkt)->r_val;
}

///@}

/**
 * Get the number of registers for a request/response r_type.
 *
 * Returns -1 on invalid argument. */
int raw_num_regs(uint8_t r_type);

/** @name Board samples and subsamples */

///@{

/** @brief Get a packet's full uint64_t experiment cookie
 * pktp may point to a struct raw_pkt_bsub or raw_pkt_bsmp. */
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

///@}

/** @brief Type-generic packet size
 * pktp may point to a struct raw_pkt_cmd, raw_pkt_bsub, or raw_pkt_bsmp. */
size_t raw_pkt_size(const void *pkt);

/*********************************************************************
 * Packet send/recv primitives.
 *
 * These convenience routines handle byte order swapping and some
 * protocol implementation details. They return a positive number on
 * success and -1 on failure, with errno set.
 */

/**
 * @name Packet byte reordering
 *
 * These convert multibyte fields to and from network byte order in
 * place.
 *
 * They return 0 on success, or -1 if the packet had garbage or
 * unrecognizable fields. */
///@{
int raw_pkt_hton(void *pkt);
int raw_pkt_ntoh(void *pkt);
///@}

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

/* Like raw_cmd_send(), but for RAW_MTYPE_BUB packets. */
ssize_t raw_bsub_send(int sockfd, struct raw_pkt_bsub *bsmp, int flags);

/* Like raw_cmd_recv(), but for RAW_MTYPE_BSUB packets. */
ssize_t raw_bsub_recv(int sockfd, struct raw_pkt_bsub *bsub, int flags);

/* Like raw_cmd_send(), but for RAW_MTYPE_BSMP packets.
 *
 * This is mostly for debugging. */
ssize_t raw_bsmp_send(int sockfd, struct raw_pkt_bsmp *bsmp, int flags);

/* Like raw_cmd_recv(), but for RAW_MTYPE_BSMP packets. */
ssize_t raw_bsmp_recv(int sockfd, struct raw_pkt_bsmp *bsmp, int flags);

/*********************************************************************
 * Stringification
 */

const char* raw_r_type_str(uint8_t r_type);
const char* raw_r_addr_str(uint8_t r_type, uint8_t r_addr);

#endif
