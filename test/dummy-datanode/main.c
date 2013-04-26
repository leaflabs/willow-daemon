/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

/*
 * Dummy datanode, used for system testing the daemon.
 */

#include <assert.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logging.h"
#include "raw_packets.h"
#include "sockutil.h"
#include "type_attrs.h"
#include "chaos.h"

#define DEFAULT_ARGUMENTS                       \
    { .chaos = 1,                               \
      .cport = 8880,                            \
      .dport = 8881,                            \
      .host = "127.0.0.1" }

struct arguments {
    const char *host;  /* Remote hostname to talk to */
    uint16_t cport;    /* Remote TCP port for command/control */
    uint16_t dport;    /* Remote UDP port listening for data packets */
    int chaos;         /* Chaos mode: randomly fail according to chaos.h */
};

static const char* program_name;

static void parse_args(struct arguments *args, int argc, char *const argv[])
{
    const char shortopts[] = "cC:D:H:";
    struct option longopts[] = {
        { .name = "chaos",
          .has_arg = optional_argument,
          .flag = 0,
          .val = 'c' },
        { .name = "cport",
          .has_arg = required_argument,
          .flag = 0,
          .val = 'C' },
        { .name = "dport",
          .has_arg = required_argument,
          .flag = 0,
          .val = 'D' },
        { .name = "remote-host",
          .has_arg = required_argument,
          .flag = 0,
          .val = 'H' },
        {0, 0, 0, 0},
    };
    while (1) {
        int option_idx = 0;
        int c = getopt_long(argc, argv, shortopts, longopts, &option_idx);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'c':
            args->chaos = strtol(optarg, (char**)0, 10);
            break;
        case 'C':
            args->cport = strtol(optarg, (char**)0, 10);
            break;
        case 'D':
            args->dport = strtol(optarg, (char**)0, 10);
            break;
        case 'h':
            args->host = optarg;
            break;
        case 0:                 /* fall through */
        case '?':               /* fall through */
        default:
            exit(EXIT_FAILURE);
        }
    }
}

#if 0                           /* FIXME port to new raw_packets.h */
static int init_and_reply(int sockfd,
                          struct raw_packet *req_pkt,
                          struct raw_packet *res_pkt,
                          uint8_t flags,
                          uint32_t value)
{
    raw_packet_init(res_pkt, RAW_PKT_TYPE_RES, flags);
    memcpy(&res_pkt->p.res, &req_pkt->p.req, sizeof(struct raw_msg_res));
    res_pkt->p.res.r_val = value;
    int ret = raw_packet_send(sockfd, res_pkt, 0);
    if (ret == -1) {
        log_ERR("error sending reply: %m");
    }
    return ret;
}

static inline int reply(int sockfd,
                        struct raw_packet *req_pkt,
                        struct raw_packet *res_pkt,
                        uint32_t value)
{
    return init_and_reply(sockfd, req_pkt, res_pkt, 0, value);
}

static inline int reply_unsupp(int sockfd,
                               struct raw_packet *req_pkt,
                               struct raw_packet *res_pkt)
{
    return init_and_reply(sockfd, req_pkt, res_pkt, RAW_FLAG_ERR, 0);
}

#define NCHIPS 32
#define NLINES 35

static int serve_sys_query(int sockfd,
                           struct raw_packet *req_pkt,
                           struct raw_packet *res_pkt)
{
    assert(req_pkt->p_type == RAW_PKT_TYPE_REQ);
    assert(req_pkt->p.req.r_type == RAW_RTYPE_SYS_QUERY);
    int ret = 0;
    switch (req_pkt->p.req.r_addr) {
    case RAW_RADDR_SYS_NCHIPS:
        log_INFO("request %u: SYS_NCHIPS, reply: %u",
                 raw_r_id(req_pkt), NCHIPS);
        if (reply(sockfd, req_pkt, res_pkt, NCHIPS) == -1) { ret = -1; }
        break;
    case RAW_RADDR_SYS_NLINES:
        log_INFO("request %u: SYS_NLINES, reply: %u",
                 raw_r_id(req_pkt), NLINES);
        if (reply(sockfd, req_pkt, res_pkt, NLINES) == -1) { ret = -1; }
        break;
    default:
        log_INFO("unsupported sys query %u", req_pkt->p.req.r_addr);
        if (reply_unsupp(sockfd, req_pkt, res_pkt) == -1) { ret = -1; }
        break;
    }
    return ret;
}

struct acquire_status {
    int acquiring;
};

static int serve_acq(int sockfd,
                     struct raw_packet *req_pkt,
                     struct raw_packet *res_pkt,
                     struct acquire_status *status)
{
    assert(req_pkt->p_type == RAW_PKT_TYPE_REQ);
    uint8_t flags = 0;
    switch (req_pkt->p.req.r_type) {
    case RAW_RTYPE_ACQ_START:
        log_INFO("request %u: ACQ_START", raw_r_id(req_pkt));
        if (status->acquiring) {
            log_WARNING("already acquiring!");
        }
        status->acquiring = 1;
        break;
    case RAW_RTYPE_ACQ_STOP:
        log_INFO("request %u: ACQ_STOP", raw_r_id(req_pkt));
        if (!status->acquiring) {
            log_WARNING("not acquiring!");
        }
        status->acquiring = 0;
        break;
    default:
        log_WARNING("request %u: unexpected r_type %u",
                    raw_r_id(req_pkt), raw_r_type(req_pkt));
        flags |= RAW_FLAG_ERR;
        break;
    }
    return init_and_reply(sockfd, req_pkt, res_pkt, flags, 0);
}

static int init_fakesamps(struct raw_packet **fakesamps, size_t nsamps)
{
    for (size_t i = 0; i < nsamps; i++) {
        fakesamps[i] = raw_packet_create_bsamp(NCHIPS, NLINES);
        if (fakesamps[i] == NULL) {
            return -1;
        }
        struct raw_msg_bsamp *bsamp = &fakesamps[i]->p.bsamp;
        bsamp->bs_idx = i;
        for (size_t s = 0; s < raw_bsamp_nsamps(bsamp); s++) {
            bsamp->bs_samples[s] = (uint16_t)s;
        }
    }
    return 0;
}

/* Serve up some board samples. For now, refuses to do so if
 * acquisition is ongoing. */
#define NFAKESAMPS 15
static int serve_samp(int res_sockfd,
                      int samp_sockfd,
                      struct raw_packet *req_pkt,
                      struct raw_packet *res_pkt,
                      struct acquire_status *status) {
    static struct raw_packet *fakesamps[NFAKESAMPS] = {NULL};
    static struct raw_packet *send_bsamp = NULL; /* copy for sending */

    if (fakesamps[0] == NULL) {
        if (init_fakesamps(fakesamps, NFAKESAMPS) == -1 ||
            init_fakesamps(&send_bsamp, 1) == -1) {
            log_ERR("can't initialize fake samples; aborting");
            exit(EXIT_FAILURE);
        }
        fakesamps[NFAKESAMPS - 1]->p_flags |= RAW_FLAG_BSAMP_IS_LAST;
    }

    assert(req_pkt->p_type == RAW_PKT_TYPE_REQ);
    assert(raw_r_type(req_pkt) == RAW_RTYPE_SAMP_READ);

    uint8_t nsamps = raw_r_addr(req_pkt);
    uint32_t start_samp = raw_r_val(req_pkt);

    log_INFO("request %u: SAMP_READ, start sample %u, nsamples %u",
             raw_r_id(req_pkt), start_samp, nsamps);

    /* Error checking and bounds clamping. */
    if (status->acquiring || nsamps == 0) {
        log_INFO("not acquiring or zero samples requested; bailing");
        init_and_reply(res_sockfd, req_pkt, res_pkt, RAW_FLAG_ERR, 0);
        return -1;
    }
    if (start_samp > NFAKESAMPS - 1) {
        log_INFO("start sample %u exceeds total; bailing", start_samp);
        init_and_reply(res_sockfd, req_pkt, res_pkt, RAW_FLAG_BSAMP_ESIZE, 0);
        return -1;
    }
    if (nsamps + start_samp > NFAKESAMPS) {
        nsamps = NFAKESAMPS - start_samp;
        log_INFO("clamped number of samples to %u", nsamps);
    }

    /* Everything looks legit; let's ship the packets. Errors
     * simulated as determined by chaos.h API. */
    init_and_reply(res_sockfd, req_pkt, res_pkt, 0, 0);
    int ret = 0;
    for (uint8_t s = 0; s < nsamps; s++) {
        /* Simulate packet loss. */
        if (chaos_bs_drop_p()) {
            log_INFO("chaos: dropping board sample %u/%u", s, nsamps);
            continue;
        }
        /* No simulated packet loss; actually try to ship it. */
        while (1) {
            uint32_t samp_idx = start_samp + (uint32_t)s;
            raw_packet_copy(send_bsamp, fakesamps[samp_idx]);
            if (raw_packet_send(samp_sockfd, send_bsamp, 0) == -1) {
                /* That's a real network error. */
                log_INFO("actually failed to send packet %u/%u", s, nsamps);
                ret = -1;
            }
            /* Simulate packet duplication. */
            if (chaos_bs_dup_p()) {
                log_INFO("chaos: sending sample %u/%u again", s, nsamps);
                continue;
            } else {
                break;
            }
        }
    }
    return ret;
}

/* Create a command/control socket and serve requests from it for as
 * long as possible. Returns an exit status if an unrecoverable error
 * occurs. */
static int serve_requests(struct arguments *args)
{
    int cc_sock = sockutil_get_tcp_passive(args->cport);
    if (cc_sock == -1) {
        log_ERR("can't make cc_sock: %m");
        return EXIT_FAILURE;
    }
    int sockfd = accept(cc_sock, NULL, 0);
    if (sockfd == -1) {
        log_ERR("can't accept() on cc_sock: %m");
        goto bail;
    }
    int bsamp_sockfd = sockutil_get_udp_connected_p(args->host, args->dport);

    struct raw_packet req_pkt = RAW_REQ_INIT;
    struct raw_packet res_pkt = RAW_RES_INIT;

    struct acquire_status acq_status = {
        .acquiring = 0,
    };

    while (1) {
        /* Get the request. */
        raw_packet_init(&req_pkt, RAW_PKT_TYPE_REQ, 0);
        int recv_val = raw_packet_recv(sockfd, &req_pkt, 0);
        if (recv_val == -1) {
            log_ERR("can't receive request: %m");
            goto bail;
        }
        if (recv_val == 0) {
            log_INFO("remote shutdown detected");
            assert(close(sockfd) == 0);
            sockfd = accept(cc_sock, NULL, 0);
            if (sockfd == -1) {
                log_ERR("can't accept(): %m");
                goto bail;
            }
            continue;
        }
        if (req_pkt.p_flags & RAW_FLAG_ERR) {
            log_INFO("received request with error flag set; ignoring it");
            continue;
        }
        /* Respond to it if we can. */
        switch (req_pkt.p.req.r_type) {
        case RAW_RTYPE_SYS_QUERY:
            if (serve_sys_query(sockfd, &req_pkt, &res_pkt) == -1) {
                goto bail;
            }
            break;
        case RAW_RTYPE_ACQ_START: /* fall through */
        case RAW_RTYPE_ACQ_STOP:
            if (serve_acq(sockfd, &req_pkt, &res_pkt, &acq_status) == -1) {
                goto bail;
            }
            break;
        case RAW_RTYPE_SAMP_READ:
            if (serve_samp(sockfd, bsamp_sockfd, &req_pkt, &res_pkt,
                           &acq_status) == -1) {
                log_INFO("failed to serve samples");
            }
            break;
        case RAW_RTYPE_SYS_CFG:    /* fall through (TODO) */
        case RAW_RTYPE_CHIP_CFG:   /* fall through (TODO) */
        case RAW_RTYPE_CHIP_QUERY: /* fall through (TODO) */
        default:
            if (reply_unsupp(sockfd, &req_pkt, &res_pkt) == -1) {
                goto bail;
            }
            break;
        }
    }

 bail:
    if (sockfd != -1 && close(sockfd) == -1) {
        log_ERR("can't close socket connected to remote: %m");
    }
    if (close(cc_sock) == -1) {
        log_ERR("can't close cc_sock: %m");
    }
    return EXIT_FAILURE;
}
#endif

/* FIXME remove when above is ported to new raw_packets.h */
static int serve_requests(__unused struct arguments *args)
{
    log_ERR("need to port to new raw_packets.h");
    return EXIT_FAILURE;
}

int main(int argc, char *argv[])
{
    /* Setup */
    int log_to_stderr = 1;
    struct arguments args = DEFAULT_ARGUMENTS;
    char *pnamep = strrchr(argv[0], '/');
    if (pnamep != NULL) {
        pnamep++;
    } else {
        pnamep = argv[0];
    }
    program_name = strdup(pnamep);
    if (!program_name) {
        fprintf(stderr, "out of memory\n");
        exit(EXIT_FAILURE);
    }
    logging_init(program_name, LOG_DEBUG, log_to_stderr);
    parse_args(&args, argc, argv);
    log_INFO("remote host: %s, C/C port %u, data port %u, chaos: %s",
             args.host, args.cport, args.dport,
             args.chaos ? "enabled" : "disabled");
    chaos_init(args.chaos);
    int ret = serve_requests(&args);
    logging_fini();
    exit(ret);
}
