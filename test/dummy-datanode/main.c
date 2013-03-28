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

#define DEFAULT_ARGUMENTS { .cport = 8880, .dport = 8881 }

struct arguments {
    uint16_t cport;    /* Client command and control port */
    uint16_t dport;    /* UDP port listening for data packets */
};

static const char* program_name;

static void parse_args(struct arguments *args, int argc, char *const argv[])
{
    const char shortopts[] = "C:D:";
    struct option longopts[] = {
        { .name = "cport",
          .has_arg = required_argument,
          .flag = 0,
          .val = 'C' },
        { .name = "dport",
          .has_arg = required_argument,
          .flag = 0,
          .val = 'D' },
        {0, 0, 0, 0},
    };
    while (1) {
        int option_idx = 0;
        int c = getopt_long(argc, argv, shortopts, longopts, &option_idx);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'C':
            args->cport = strtol(optarg, (char**)0, 10);
        case 'D':
            args->dport = strtol(optarg, (char**)0, 10);
            break;
        case 0:                 /* fall through */
        case '?':               /* fall through */
        default:
            exit(EXIT_FAILURE);
        }
    }
}

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
    int ret = 0;
    switch (req_pkt->p.req.r_addr) {
    case RAW_RADDR_SYS_NCHIPS:
        log_INFO("request %u:SYS_NCHIPS, reply: %u", NCHIPS);
        if (reply(sockfd, req_pkt, res_pkt, NCHIPS) == -1) { ret = -1; }
        break;
    case RAW_RADDR_SYS_NLINES:
        log_INFO("request %u: SYS_NLINES, reply: %u", NLINES);
        if (reply(sockfd, req_pkt, res_pkt, NLINES) == -1) { ret = -1; }
        break;
    default:
        log_INFO("unsupported request %u", req_pkt->p_type);
        if (reply_unsupp(sockfd, req_pkt, res_pkt) == -1) { ret = -1; }
        break;
    }
    return ret;
}

static int serve_requests(struct arguments *args)
{
    int cc_sock = sockutil_get_tcp_passive(args->cport);
    if (cc_sock == -1) {
        log_ERR("can't make cc_sock");
        return EXIT_FAILURE;
    }
    int sockfd = accept(cc_sock, NULL, 0);
    if (sockfd == -1) {
        log_ERR("can't accept() on cc_sock: %m");
        goto bail;
    }

    struct raw_packet req_pkt = RAW_REQ_INIT;
    struct raw_packet res_pkt = RAW_RES_INIT;

    while (1) {
        /* Get the request. */
        raw_packet_init(&req_pkt, RAW_PKT_TYPE_REQ, 0);
        int recv_val = raw_packet_recv(sockfd, &req_pkt, NULL, 0);
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

int main(int argc, char *argv[])
{
    /* Setup */
    int log_to_stderr = 1;
    struct arguments args = DEFAULT_ARGUMENTS;
    program_name = strdup(argv[0]);
    if (!program_name) {
        fprintf(stderr, "out of memory\n");
        exit(EXIT_FAILURE);
    }
    logging_init(program_name, LOG_DEBUG, log_to_stderr);
    parse_args(&args, argc, argv);

    /* Serve requests */
    log_INFO("client command port: %u", args.cport);
    log_INFO("daemon data port: %u", args.dport);
    int ret = serve_requests(&args);
    logging_fini();
    exit(ret);
}
