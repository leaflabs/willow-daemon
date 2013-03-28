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

static int do_client_request(int sockfd,
                             struct raw_packet *req,
                             struct raw_packet *res) {
    assert(req->p_type == RAW_PKT_TYPE_REQ);
    assert(res->p_type == RAW_PKT_TYPE_RES);
    uint16_t req_id = req->p.req.r_id;
    if (raw_packet_send(sockfd, req, 0) == -1) {
        log_ERR("can't send request: %m");
        return -1;
    }
    uint8_t packtype = RAW_PKT_TYPE_RES;
    if (raw_packet_recv(sockfd, res, &packtype, 0) == -1) {
        log_ERR("can't get response: %m");
        return -1;
    }
    if (res->p.res.r_id != req_id) {
        log_ERR("expected response r_id=%u, but got %u",
                req_id, res->p.res.r_id);
        return -1;
    }
    return 0;
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

    /* For getting remote's data packet configuration */
    struct {
        uint16_t n_fpga_chips;
        uint16_t n_chan_per_chip;
    } client_config;
    struct raw_packet req_pkt = RAW_REQ_INIT;
    struct raw_packet res_pkt = RAW_RES_INIT;
    struct raw_msg_req *req = &req_pkt.p.req;
    struct raw_msg_res *res = &res_pkt.p.res;
    uint16_t cur_req_id = 0;

    log_INFO("reading number of FPGA chips");
    raw_packet_init(&req_pkt, RAW_PKT_TYPE_REQ, 0);
    raw_packet_init(&res_pkt, RAW_PKT_TYPE_RES, 0);
    req->r_id = cur_req_id++;
    req->r_type = RAW_RTYPE_SYS_QUERY;
    req->r_addr = RAW_RADDR_SYS_NCHIPS;
    if (do_client_request(cc_sock, &req_pkt, &res_pkt) == -1) {
        goto bail;
    }
    client_config.n_fpga_chips = (uint16_t)res->r_val;

    log_INFO("reading number of channels per chip");
    raw_packet_init(&req_pkt, RAW_PKT_TYPE_REQ, 0);
    raw_packet_init(&res_pkt, RAW_PKT_TYPE_RES, 0);
    req->r_id = cur_req_id++;
    req->r_type = RAW_RTYPE_SYS_QUERY;
    req->r_addr = RAW_RADDR_SYS_NLINES;
    if (do_client_request(cc_sock, &req_pkt, &res_pkt) == -1) {
        goto bail;
    }
    client_config.n_chan_per_chip = (uint16_t)res->r_val;

    /* For now, just log the results. */
    log_INFO("client reports data dimensions %ux%u",
             client_config.n_fpga_chips, client_config.n_chan_per_chip);
    ret = EXIT_SUCCESS;

 bail:
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
