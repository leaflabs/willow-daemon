/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/select.h>

#include "daemon.h"
#include "logging.h"

#include "proto/open-ephys.pb-c.h"

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

void write_fchunk_to(int fd)
{
    int32_t readings[] = {0xAA, 0x55, 0x00, 0xFF};
    FrameChunk fchunk = FRAME_CHUNK__INIT;
    size_t packed_size;
    void *packed_buf;

    /* Initialize fchunk. */
    fchunk.has_startchannel = 1;
    fchunk.startchannel = 0;
    fchunk.n_readings = sizeof(readings) / sizeof(readings[0]);
    fchunk.readings = readings;

    /* Pack to wire format. */
    packed_size = frame_chunk__get_packed_size(&fchunk);
    packed_buf = malloc(packed_size);
    if (packed_buf == 0) {
        log_ERR("%m");
        exit(EXIT_FAILURE);
    }
    frame_chunk__pack(&fchunk, packed_buf);

    /* Write packed protocol buffer to file. */
    if (write(fd, packed_buf, packed_size) == -1) {
        log_ERR("can't write to protobuf file: %m");
        exit(EXIT_FAILURE);
    }
    log_DEBUG("wrote %zu bytes to file", packed_size);
}

int main(int argc, char *argv[])
{
    struct arguments args;
    const char out_path[] = "/tmp/fchunk-wire-fmt";

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

    /* Write to out_path. */
    int out_fd = open(out_path, O_RDWR | O_CREAT, 0644);
    if (out_fd == -1) {
        log_ERR("can't open %s: %m", out_path);
        exit(EXIT_FAILURE);
    }
    write_fchunk_to(out_fd);
    close(out_fd);

    logging_fini();
    return 0;
}
