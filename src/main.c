/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/select.h>

#include <hdf5.h>

#include "daemon.h"
#include "logging.h"

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

/* Encapsulates results of command-line arguments. */
struct arguments {
    int dont_daemonize;         /* Skip daemonization. */
};

void parse_args(struct arguments* args, int argc, char *const argv[])
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

/*
 * Writes fake data to an HDF5 file, overwriting its previous contents.
 */
#define DUMMY_DATA_LEN (20 * 60 * 1024 * 1024) /* 60MB is ~1 second of data */
#define IS_LITTLE_ENDIAN (1 == *(unsigned char *)&(const int){1})
static int write_h5_file(const char out_file_path[])
{
    int ret = -1;
    uint16_t *data = malloc(sizeof(uint16_t) * DUMMY_DATA_LEN);
    herr_t err;

    /* Initialize dummy data. */
    if (!data) {
        log_ERR("out of memory");
        goto nomem;
    }
    log_DEBUG("initializing data");
    for (int i = 0; i < DUMMY_DATA_LEN; i++) {
        data[i] = (uint16_t)(0xFFFF * i / DUMMY_DATA_LEN);
    }

    /* Jump through hoops. */
    log_INFO("opening %s and doing HDF5 setup", out_file_path);
    hid_t file = H5Fcreate(out_file_path, H5F_ACC_TRUNC, H5P_DEFAULT,
                           H5P_DEFAULT);
    if (file < 0) {
        log_ERR("can't create file");
        goto nofile;
    }

    const hsize_t dim = DUMMY_DATA_LEN;
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
    err = H5Tset_order(data_type, (IS_LITTLE_ENDIAN ?
                                   H5T_ORDER_LE :
                                   H5T_ORDER_BE));
    if (err < 0) {
        log_ERR("can't set byte order");
        goto noorder;
    }

    time_t t_start, t_finish;

    log_DEBUG("starting write");
    time(&t_start);
    hid_t data_set = H5Dcreate(file, "awesome dataset", data_type, data_space,
                               H5P_DEFAULT);
    if (data_set < 0) {
        log_ERR("can't create data set");
        goto noset;
    }

    /* Actually write the data. */
    err = H5Dwrite(data_set, H5T_NATIVE_USHORT, H5S_ALL, H5S_ALL,
                   H5P_DEFAULT, data);
    if (err < 0) {
        log_ERR("can't write data to %s", out_file_path);
    }
    /* Flush data, to try to get better ideas about time. */
    err = H5Fflush(file, H5F_SCOPE_LOCAL);
    if (err < 0) {
        log_ERR("can't write data to %s", out_file_path);
    }
    sync();
    time(&t_finish);

    /* Success! */
    size_t nbytes = DUMMY_DATA_LEN * sizeof(data[0]);
    double t_diff = difftime(t_finish, t_start);
    double kb_sec = nbytes / t_diff / 1024.0 / 1024.0;
    log_DEBUG("wrote %u records, %f sec, %f MB/sec",
              DUMMY_DATA_LEN, t_diff, kb_sec);
    ret = 0;

    log_DEBUG("closing data set");
    H5Dclose(data_set);
 noset:
 noorder:
    log_DEBUG("closing data type");
    H5Tclose(data_type);
 notype:
    log_DEBUG("closing data space");
    H5Sclose(data_space);
 nospace:
    log_DEBUG("closing file");
    H5Fclose(file);
 nofile:
    log_DEBUG("freeing data");
    free(data);
 nomem:
    return ret;
}

int main(int argc, char *argv[])
{
    struct arguments args;

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

    write_h5_file("/tmp/foo.h5");

    logging_fini();
    return 0;
}
