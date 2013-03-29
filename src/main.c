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

#include <hdf5.h>

#include "daemon.h"
#include "logging.h"
#include "sockutil.h"
#include "type_attrs.h"
#include "raw_packets.h"

/* main() initializes this before doing anything else. */
static const char* program_name;

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

__unused
static uint16_t* init_raw_data(size_t len)
{
    uint16_t *data = malloc(len * sizeof(uint16_t));

    /* Initialize dummy data. */
    if (!data) {
        log_ERR("out of memory");
        return 0;
    }
    log_DEBUG("initializing dummy data");
    for (size_t i = 0; i < len; i++) {
        data[i] = (uint16_t)(0xFFFF / len * i);
    }
    return data;
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

/*
 * Writes raw data to file, overwriting its previous contents.
 */
__unused
static int write_raw_file(uint16_t *data, size_t len,
                          const char out_file_path[])
{
    int ret = -1;
    size_t nbytes = len * sizeof(uint16_t);
    struct timeval t_start, t_finish;

    log_DEBUG("opening %s", out_file_path);
    int fd = open(out_file_path, O_RDWR | O_TRUNC | O_CREAT, 0644);
    if (fd == -1) {
        log_ERR("can't open file: %m");
        goto noopen;
    }

    /* Write file. */
    log_DEBUG("starting raw write");
    gettimeofday(&t_start, 0);
    size_t nwritten = 0;
    while (nwritten < nbytes) {
        ssize_t written = write(fd, (char*)data + nwritten, nbytes - nwritten);
        if (written <= 0) {
            log_ERR("write failed: %m");
            goto nowrite;
        }
        nwritten += written;
    }
    sync();
    gettimeofday(&t_finish, 0);

    assert(nbytes == nwritten);

    /* Success. */
    log_results(len, nbytes, &t_start, &t_finish);

 nowrite:
    ret = close(fd);
    if (ret != 0) {
        log_ERR("can't close %s: %m", out_file_path);
    }
 noopen:
    return ret;
}

/*
 * Writes fake data to an HDF5 file, overwriting its previous contents.
 */
#define IS_LITTLE_ENDIAN (1 == *(unsigned char *)&(const int){1})
__unused
static int write_h5_file(uint16_t *data, size_t len,
                         const char out_file_path[])
{
    int ret = -1;
    size_t nbytes = len * sizeof(uint16_t);
    struct timeval t_start, t_finish;

    /* Do setup work. */
    log_DEBUG("opening %s and doing HDF5 setup", out_file_path);
    hid_t file = H5Fcreate(out_file_path, H5F_ACC_TRUNC, H5P_DEFAULT,
                           H5P_DEFAULT);
    if (file < 0) {
        log_ERR("can't create file");
        goto nofile;
    }

    const hsize_t dim = len;
    hid_t data_space = H5Screate_simple(1, &dim, NULL);
    if (data_space < 0) {
        log_ERR("can't create data space");
        goto nospace;
    }

    assert(sizeof(unsigned short) == 2);
    hid_t data_type = H5Tcopy(H5T_NATIVE_USHORT);
    if (data_type < 0) {
        log_ERR("can't create data type");
        goto notype;
    }
    herr_t err = H5Tset_order(data_type, (IS_LITTLE_ENDIAN ?
                                          H5T_ORDER_LE :
                                          H5T_ORDER_BE));
    if (err < 0) {
        log_ERR("can't set byte order");
        goto noorder;
    }

    /* Create dataset and write the data. */
    log_DEBUG("starting write");
    gettimeofday(&t_start, 0);
    hid_t data_set = H5Dcreate(file, "awesome dataset", data_type, data_space,
                               H5P_DEFAULT);
    if (data_set < 0) {
        log_ERR("can't create data set");
        goto noset;
    }
    err = H5Dwrite(data_set, H5T_NATIVE_USHORT, H5S_ALL, H5S_ALL,
                   H5P_DEFAULT, data);
    if (err < 0) {
        log_ERR("can't write data to %s", out_file_path);
    }
    /* Flush HDF5 caches. */
    err = H5Fflush(file, H5F_SCOPE_LOCAL);
    if (err < 0) {
        log_ERR("can't write data to %s", out_file_path);
    }
    /* Flush system cache. */
    sync();
    gettimeofday(&t_finish, 0);

    /* Success! */
    log_results(len, nbytes, &t_start, &t_finish);
    ret = 0;

    log_DEBUG("doing HDF5 teardown");
    H5Dclose(data_set);
 noset:
 noorder:
    H5Tclose(data_type);
 notype:
    H5Sclose(data_space);
 nospace:
    H5Fclose(file);
 nofile:
    return ret;
}

/* Do a request, wait for response, write .r_val to valptr if it's not
 * NULL.  Assumes req_pkt->p.req is valid already. */
static int do_req_res(int sockfd,
                      struct raw_packet *req_pkt,
                      struct raw_packet *res_pkt,
                      uint32_t *valptr)
{
    raw_packet_init(req_pkt, RAW_PKT_TYPE_REQ, 0);
    raw_packet_init(res_pkt, RAW_PKT_TYPE_RES, 0);
    uint16_t req_id = raw_r_id(req_pkt); /* cache; sending mangles it. */
    if (raw_packet_send(sockfd, req_pkt, 0) == -1) {
        log_ERR("can't send request: %m");
        return -1;
    }
    uint8_t packtype = RAW_PKT_TYPE_RES;
    if (raw_packet_recv(sockfd, res_pkt, &packtype, 0) == -1) {
        log_ERR("can't get response: %m");
        return -1;
    }
    uint16_t res_id = raw_r_id(res_pkt);
    if (res_id != req_id) {
        log_ERR("expected response r_id=%u, but got %u", req_id, res_id);
        return -1;
    }
    if (raw_packet_err(res_pkt)) {
        log_ERR("request returned error; flags 0x%x", res_pkt->p_flags);
        return -1;
    }
    if (valptr != NULL) {
        *valptr = raw_r_val(res_pkt);
    }
    return 0;
}

struct dnode_config {
  uint32_t n_chip;
  uint32_t n_chan_p_chip;
};

static int read_dnode_config(int cc_sock,
                             struct dnode_config *dcfg,
                             struct raw_packet *req_pkt,
                             struct raw_packet *res_pkt,
                             uint16_t *cur_req_id)
{
    struct raw_msg_req *req = &req_pkt->p.req;

    log_INFO("reading number of FPGA chips");
    req->r_id = (*cur_req_id)++;
    req->r_type = RAW_RTYPE_SYS_QUERY;
    req->r_addr = RAW_RADDR_SYS_NCHIPS;
    if (do_req_res(cc_sock, req_pkt, res_pkt, &dcfg->n_chip) == -1) {
      return -1;
    }

    log_INFO("reading number of channels per chip");
    req->r_id = (*cur_req_id)++;
    *cur_req_id += 1;
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
                                struct raw_packet *res_pkt,
                                uint16_t *cur_req_id)
{
    struct raw_msg_req *req = &req_pkt->p.req;

    log_INFO("starting acquisition");
    req->r_id = (*cur_req_id)++;
    req->r_type = RAW_RTYPE_ACQ_START;
    if (do_req_res(cc_sock, req_pkt, res_pkt, NULL) == -1) {
        return -1;
    }

    log_INFO("stopping acquisition");
    req->r_id = (*cur_req_id)++;
    req->r_type = RAW_RTYPE_ACQ_STOP;
    if (do_req_res(cc_sock, req_pkt, res_pkt, NULL) == -1) {
        return -1;
    }
    return 0;
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

/* Data node's hostname and command/control port, and local packet
 * data port. */
#define DNODE_HOST "127.0.0.1"
#define DNODE_CC_PORT 8880
#define PACKET_DATA_PORT 8881
static int daemon_main(void)
{
    int ret = EXIT_FAILURE;

    int cc_sock = sockutil_get_tcp_connected_p(DNODE_HOST, DNODE_CC_PORT);
    if (cc_sock == -1) {
        log_ERR("can't connect to %s port %d: %m",
                DNODE_HOST, DNODE_CC_PORT);
        goto nocc;
    }
    int dt_sock = sockutil_get_udp_socket(PACKET_DATA_PORT);
    if (dt_sock == -1) {
        log_ERR("can't create packet data socket on port %d: %m",
                PACKET_DATA_PORT);
        goto nodt;
    }

    /* For talking to remote */
    struct dnode_config dcfg;
    struct raw_packet req_pkt = RAW_REQ_INIT;
    struct raw_packet res_pkt = RAW_RES_INIT;
    struct raw_msg_req *req = &req_pkt.p.req;
    uint16_t cur_req_id = 0;

    if (read_dnode_config(cc_sock, &dcfg, &req_pkt, &res_pkt,
                          &cur_req_id) == -1) {
        goto bail;
    }

    struct raw_packet *bsamp_pkt = raw_packet_create_bsamp(dcfg.n_chip,
                                                           dcfg.n_chan_p_chip);
    if (bsamp_pkt == NULL) {
        goto bail;
    }

    if (do_recording_session(cc_sock, &req_pkt, &res_pkt, &cur_req_id) == -1) {
        goto bail;
    }

    /* TODO serve protobuf requests forever */
    /* FIXME resilience in the face of wedged/confused datanodes */
    log_INFO("reading out packets");
    int got_last_packet = 0;
    uint32_t samp_idx = 0;
    const struct timespec timeout = {
        .tv_sec = 0,
        .tv_nsec = 100 * 1000 * 1000, /* 100 msec */
    };
    while (!got_last_packet) {
        req->r_id = cur_req_id++;
        req->r_type = RAW_RTYPE_SAMP_READ;
        req->r_addr = 1;
        req->r_val = samp_idx;
        log_INFO("request %u for board sample %u", req->r_id, samp_idx);
        if (do_req_res(cc_sock, &req_pkt, &res_pkt, NULL) == -1) {
            goto bail;
        }
        if (raw_packet_err(&res_pkt)) {
            log_ERR("exiting due to error in response; flags 0x%x",
                    res_pkt.p_flags);
        }
        /* Read from dt_sock until we get what we want or we time out. */
        int rpts;
        while (1) {
            rpts = read_packet_timeout(dt_sock, bsamp_pkt, &timeout);
            if (rpts <= 0) { break; } /* Error or timeout */

            /* We got something; sanity-check the packet. */
            struct raw_msg_bsamp *bs = &bsamp_pkt->p.bsamp;
            if (bs->bs_nchips != dcfg.n_chip ||
                bs->bs_nlines != dcfg.n_chan_p_chip) {
                log_INFO("ignoring packet with unexpected dimensions %ux%u",
                         bs->bs_nchips, bs->bs_nlines);
                continue;
            } else if (bs->bs_idx != samp_idx) {
                log_INFO("ignoring unexpected sample number %u", bs->bs_idx);
                continue;
            } else if (raw_packet_err(bsamp_pkt)) {
                log_ERR("board sample %u reports error (flags 0x%x); bailing",
                        samp_idx, bsamp_pkt->p_flags);
                goto bail;      /* TODO something smarter */
            }
            log_INFO("got board sample %u", bs->bs_idx);
            break;
        }
        /* See if we exited due to error or timeout. */
        switch (rpts) {
        case -1:
            log_ERR("error on request for board sample %u; bailing: %m",
                    samp_idx);
            goto bail;
        case 0:
            log_INFO("request for board sample %u timed out; retrying",
                     samp_idx);
            continue;
        default:
            /* success! */
            break;
        }
        /* TODO write board sample to some fixed file
         * TODO remember where we put it so protobuf can ask for it */
        got_last_packet = bsamp_pkt->p_flags & RAW_FLAG_BSAMP_IS_LAST;
        if (got_last_packet) {
            log_INFO("that's the last packet");
        }
        samp_idx++;
    }

    ret = EXIT_SUCCESS;

 bail:
    if (ret == EXIT_FAILURE) {
        log_ERR("exiting due to error");
    }
    if (close(dt_sock) != 0) {
        log_ERR("unable to close data socket: %m");
    }
 nodt:
    if (close(cc_sock) != 0) {
        log_ERR("unable to close command/control socket: %m");
    }
 nocc:
    return ret;
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
