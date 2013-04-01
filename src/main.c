/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "daemon.h"
#include "logging.h"
#include "sockutil.h"
#include "type_attrs.h"
#include "raw_packets.h"
#include "hdf5_ch_storage.h"
#include "raw_ch_storage.h"

/* main() initializes this before doing anything else. */
static const char* program_name;

/* Data node's hostname and command/control port, and local packet
 * data port. */
#define DNODE_HOST "127.0.0.1"
#define DNODE_CC_PORT 8880
#define PACKET_DATA_PORT 8881

/* Whether to store data into HDF5 (==1) or just do raw write() (==0;
 * for benchmarking). */
#define DO_HDF5_STORAGE 0

/* Local file to start storing in. This gets truncated each time you
 * run the daemon. */
#if DO_HDF5_STORAGE
#define PACKET_DATA_FILE "/media/sngtest-xfs/packet_data.h5"
#else
#define PACKET_DATA_FILE "/media/sngtest-xfs/packet_data.raw"
#endif
#define PACKET_DATASET_NAME "ANONYMOUS_DATASET"

/* Data node configuration */
struct dnode_config {
  uint32_t n_chip;
  uint32_t n_chan_p_chip;
};

static void usage(int exit_status)
{
    printf("Usage: %s\n"
           "Options:\n"
           "  -h, --help\t\tPrint this message\n"
           "  -N, --dont-daemonize\tSkip daemonization\n",
           program_name);
    exit(exit_status);
}

#define DEFAULT_ARGUMENTS { .dont_daemonize = 0 }

/* Encapsulates results of command-line arguments. */
struct arguments {
    int dont_daemonize;         /* Skip daemonization. */
};

static void parse_args(struct arguments* args, int argc, char *const argv[])
{
    int print_usage = 0;
    const char shortopts[] = "hN";
    struct option longopts[] = {
        /* Keep these sorted with shortopts. */
        { .name = "help",       /* -h */
          .has_arg = no_argument,
          .flag = &print_usage,
          .val = 1 },
        { .name = "dont-daemonize", /* -N */
          .has_arg = no_argument,
          .flag = &args->dont_daemonize,
          .val = 1 },
        {0, 0, 0, 0},
    };
    while (1) {
        int option_idx = 0;
        int c = getopt_long(argc, argv, shortopts, longopts, &option_idx);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 0:
            /* Check print_usage, which we treat as a special case. */
            if (print_usage) {
                usage(EXIT_SUCCESS);
            }
            /* Otherwise, getopt_long() has set *flag=val, so there's
             * nothing to do until we take long commands with
             * arguments. When that happens,
             * `longopts[option_idx].name' was given, with argument
             * `optarg'. */
            break;
        case 'h':
            usage(EXIT_SUCCESS);
        case 'N':
            args->dont_daemonize = 1;
            break;
        case '?': /* Fall through. */
        default:
            usage(EXIT_FAILURE);
        }
    }
}

static void try_open_dnode_sockets(int *cc_sock, int *dt_sock)
{
    if (cc_sock) {
        *cc_sock = sockutil_get_tcp_connected_p(DNODE_HOST, DNODE_CC_PORT);
    }
    if (dt_sock) {
        *dt_sock = sockutil_get_udp_socket(PACKET_DATA_PORT);
    }
}

/* Do a request, wait for response, write .r_val to valptr if it's not
 * NULL.  Assumes req_pkt->p.req is valid already. */
static int do_req_res(int sockfd,
                      struct raw_packet *req_pkt,
                      struct raw_packet *res_pkt,
                      uint32_t *valptr)
{
    int ret = -1;
    raw_packet_init(req_pkt, RAW_PKT_TYPE_REQ, 0);
    raw_packet_init(res_pkt, RAW_PKT_TYPE_RES, 0);
    uint16_t req_id = raw_r_id(req_pkt); /* cache. */
    req_pkt->p.req.r_id = req_id;
    if (raw_packet_send(sockfd, req_pkt, 0) == -1) {
        log_ERR("can't send request: %m");
        goto out;
    }
    uint8_t packtype = RAW_PKT_TYPE_RES;
    if (raw_packet_recv(sockfd, res_pkt, &packtype, 0) == -1) {
        log_ERR("can't get response: %m");
        goto out;
    }
    uint16_t res_id = raw_r_id(res_pkt);
    if (res_id != req_id) {
        log_ERR("expected response r_id=%u, but got %u", req_id, res_id);
        goto out;
    }
    if (raw_packet_err(res_pkt)) {
        log_ERR("request returned error; flags 0x%x", res_pkt->p_flags);
        goto out;
    }
    ret = 0;
    if (valptr != NULL) {
        *valptr = raw_r_val(res_pkt);
    }
 out:
    req_pkt->p.req.r_id = req_id + 1;
    return ret;
}

static int read_dnode_config(int cc_sock,
                             struct dnode_config *dcfg,
                             struct raw_packet *req_pkt,
                             struct raw_packet *res_pkt)
{
    struct raw_msg_req *req = &req_pkt->p.req;

    log_INFO("reading number of FPGA chips");
    req->r_type = RAW_RTYPE_SYS_QUERY;
    req->r_addr = RAW_RADDR_SYS_NCHIPS;
    if (do_req_res(cc_sock, req_pkt, res_pkt, &dcfg->n_chip) == -1) {
      return -1;
    }

    log_INFO("reading number of channels per chip");
    req->r_type = RAW_RTYPE_SYS_QUERY;
    req->r_addr = RAW_RADDR_SYS_NLINES;
    if (do_req_res(cc_sock, req_pkt, res_pkt, &dcfg->n_chan_p_chip) == -1) {
      return -1;
    }

    log_INFO("client reports data dimensions %ux%u",
             dcfg->n_chip, dcfg->n_chan_p_chip);
    return 0;
}

/* Dummy version of a session recording routine. Just starts/stops;
 * for now, we're assuming that the remote is the dummy datanode. */
static int do_recording_session(int cc_sock,
                                struct raw_packet *req_pkt,
                                struct raw_packet *res_pkt)
{
    struct raw_msg_req *req = &req_pkt->p.req;

    log_INFO("starting acquisition");
    req->r_type = RAW_RTYPE_ACQ_START;
    if (do_req_res(cc_sock, req_pkt, res_pkt, NULL) == -1) {
        return -1;
    }

    log_INFO("stopping acquisition");
    req->r_type = RAW_RTYPE_ACQ_STOP;
    if (do_req_res(cc_sock, req_pkt, res_pkt, NULL) == -1) {
        return -1;
    }
    return 0;
}

static struct ch_storage* alloc_ch_storage(void)
{
    struct ch_storage *chns;
    if (DO_HDF5_STORAGE) {
        chns = hdf5_ch_storage_alloc(PACKET_DATA_FILE, PACKET_DATASET_NAME);
    } else {
        chns = raw_ch_storage_alloc(PACKET_DATA_FILE,
                                    O_CREAT | O_RDWR | O_TRUNC, 0644);
    }
    return chns;
}

static void free_ch_storage(struct ch_storage* chns)
{
    if (DO_HDF5_STORAGE) {
        hdf5_ch_storage_free(chns);
    } else  {
        raw_ch_storage_free(chns);
    }
}

static int read_packet_timeout(int dt_sock,
                               struct raw_packet *bsamp_pkt,
                               const struct timespec *timeout)
{
    /* TODO: consider signal safety once we e.g. accept SIGHUP */
    uint8_t *ptype = &bsamp_pkt->p_type;
    fd_set rfds;
    int maxfdp1 = dt_sock + 1;
    FD_ZERO(&rfds);
    FD_SET(dt_sock, &rfds);
    switch (pselect(maxfdp1, &rfds, NULL, NULL, timeout, NULL)) {
    case -1:
        return -1;
    case 0:
        return 0;
    case 1:
        assert(FD_ISSET(dt_sock, &rfds));
        return raw_packet_recv(dt_sock, bsamp_pkt, ptype, 0);
    default:
        log_ERR("can't happen");
        assert(0);
        return -1;
    }
}

static int copy_all_packets(int cc_sock, int dt_sock,
                            struct dnode_config *dcfg,
                            struct ch_storage *chns,
                            struct raw_packet *req_pkt,
                            struct raw_packet *res_pkt,
                            struct raw_packet *bsamp_pkt)
{
    /* FIXME resilience in the face of wedged/confused datanodes */
    log_INFO("reading out packets");
    struct raw_msg_req *req = &req_pkt->p.req;
    struct raw_msg_bsamp *bs = &bsamp_pkt->p.bsamp;
    int got_last_packet = 0;
    uint32_t samp_idx = 0;
    const struct timespec timeout = {
        .tv_sec = 0,
        .tv_nsec = 100 * 1000 * 1000, /* 100 msec */
    };
    while (!got_last_packet) {
        req->r_type = RAW_RTYPE_SAMP_READ;
        req->r_addr = 1;
        req->r_val = samp_idx;
        log_INFO("request %u for board sample %u", req->r_id, samp_idx);
        if (do_req_res(cc_sock, req_pkt, res_pkt, NULL) == -1) {
            return -1;
        }
        /* Read from dt_sock until we get what we want or we time out. */
        int rpts;
        while (1) {
            rpts = read_packet_timeout(dt_sock, bsamp_pkt, &timeout);
            if (rpts <= 0) { break; } /* Error or timeout */

            /* We got something; sanity-check the packet. */
            if (bs->bs_nchips != dcfg->n_chip ||
                bs->bs_nlines != dcfg->n_chan_p_chip) {
                log_INFO("ignoring packet with unexpected dimensions %ux%u",
                         bs->bs_nchips, bs->bs_nlines);
                continue;
            } else if (bs->bs_idx != samp_idx) {
                /* Unexpected packet index; ignore it. */
                continue;
            } else if (raw_packet_err(bsamp_pkt)) {
                log_ERR("board sample %u reports error (flags 0x%x); bailing",
                        samp_idx, bsamp_pkt->p_flags);
                return -1;      /* TODO: something smarter */
            }
            log_INFO("got board sample %u", bs->bs_idx);
            break;
        }
        /* See if we exited due to error or timeout. */
        switch (rpts) {
        case -1:
            log_ERR("error on request for board sample %u; bailing: %m",
                    samp_idx);
            return -1;        /* TODO: something smarter */
        case 0:
            continue;         /* Timeout; retry the packet request. */
        default:
            break;            /* Success! */
        }
        size_t nsamp = bs->bs_nchips * bs->bs_nlines;
        ssize_t st = chns->ops->cs_write(chns, bs->bs_samples, nsamp);
        if (st == -1 || (size_t)st < nsamp) {
            log_ERR("error writing board sample to disk");
            return -1;
        }
        /* TODO remember where we put it so protobuf can ask for it */
        got_last_packet = bsamp_pkt->p_flags & RAW_FLAG_BSAMP_IS_LAST;
        if (got_last_packet) {
            log_INFO("that's the last packet");
        }
        samp_idx++;
    }
    return 0;
}

static int daemon_main(void)
{
    int ret = EXIT_FAILURE;
    int cc_sock, dt_sock;

    /* Open connection to data node */
    try_open_dnode_sockets(&cc_sock, &dt_sock);
    if (cc_sock == -1 || dt_sock == -1) {
        log_ERR("can't connect to data node at %s port %d: %m",
                DNODE_HOST, DNODE_CC_PORT);
        goto bail;
    }

    /* Get data node configuration and do recording session */
    struct dnode_config dcfg;
    struct raw_packet req_pkt = RAW_REQ_INIT;
    struct raw_packet res_pkt = RAW_RES_INIT;

    if (read_dnode_config(cc_sock, &dcfg, &req_pkt, &res_pkt) == -1) {
        goto bail;
    }
    struct raw_packet *bsamp_pkt = raw_packet_create_bsamp(dcfg.n_chip,
                                                           dcfg.n_chan_p_chip);
    if (bsamp_pkt == NULL ||
        do_recording_session(cc_sock, &req_pkt, &res_pkt) == -1) {
        goto bail;
    }

    /* Set up channel storage */
    struct ch_storage *chns = alloc_ch_storage();
    if (!chns) {
        log_ERR("can't allocate channel storage object");
        goto bail;
    }

    /* Copy remote's packets to file */
    ret = copy_all_packets(cc_sock, dt_sock, &dcfg, chns,
                           &req_pkt, &res_pkt, bsamp_pkt);

 bail:
    if (ret == EXIT_FAILURE) {
        log_ERR("exiting due to error");
    }
    if (dt_sock != -1 && close(dt_sock) != 0) {
        log_ERR("unable to close data socket: %m");
    }
    if (cc_sock != -1 && close(cc_sock) != 0) {
        log_ERR("unable to close command/control socket: %m");
    }
    free(bsamp_pkt);
    if (chns) {
        free_ch_storage(chns);
    }
    return ret;
}

static void log_results(size_t len, size_t nbytes,
                        struct timeval *t_start,
                        struct timeval *t_finish)
{
    uint64_t usec_start = ((uint64_t)t_start->tv_sec * 1000ULL * 1000ULL +
                           (uint64_t)t_start->tv_usec);
    uint64_t usec_finish = ((uint64_t)t_finish->tv_sec * 1000ULL * 1000ULL +
                            (uint64_t)t_finish->tv_usec);
    double t_diff_sec = (usec_finish - usec_start) / 1000.0 / 1000.0;
    double mb_sec = nbytes / t_diff_sec / 1024.0 / 1024.0;
    log_DEBUG("wrote %zu records, %f sec, %f MB/sec", len, t_diff_sec, mb_sec);
}

/* TODO resurrect this for daemon_main */
__unused
static int benchmark_write(struct ch_storage *chns, uint16_t *ch_data,
                           size_t len)
{
    struct timeval t_start, t_finish;
    size_t nbytes = len * sizeof(*ch_data);

    log_DEBUG("starting write");
    gettimeofday(&t_start, 0);
    int status = chns->ops->cs_write(chns, ch_data, len);
    if (status < 0) {
        log_ERR("can't write data");
        return -1;
    }
    /* Flush storage backend cache. */
    status = chns->ops->cs_datasync(chns);
    if (status < 0) {
        log_ERR("can't sync data");
        return -1;
    }
    /* Flush system cache. */
    sync();
    gettimeofday(&t_finish, 0);

    /* Success! */
    log_results(len, nbytes, &t_start, &t_finish);
    return 0;
}

int main(int argc, char *argv[])
{
    struct arguments args = DEFAULT_ARGUMENTS;

    /* Stash the program name, parse arguments, and set up logging
     * before doing anything else. DO NOT USE printf() etc. AFTER THIS
     * POINT; use the logging.h API instead. */
    program_name = strdup(argv[0]);
    if (!program_name) {
        fprintf(stderr, "Out of memory at startup\n");
        exit(EXIT_FAILURE);
    }
    parse_args(&args, argc, argv);
    int log_to_stderr = args.dont_daemonize;
    logging_init(program_name, LOG_DEBUG, log_to_stderr);

    /* Become a daemon. */
    fd_set leave_open;
    FD_ZERO(&leave_open);
    if (!args.dont_daemonize && (daemonize(&leave_open, 0) == -1)) {
        log_EMERG("can't daemonize: %m");
        exit(EXIT_FAILURE);
    }

    /* Go! */
    int ret = daemon_main();
    logging_fini();
    return ret;
}
