/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/select.h>

#include "daemon.h"
#include "proto/open-ephys.pb-c.h"

static void usage(const char *program_name, int exit_status)
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
                usage(argv[0], EXIT_SUCCESS);
            }
            /* Otherwise, getopt_long() has set *flag=val, so there's
             * nothing to do until we take long commands with
             * arguments. When that happens,
             * `longopts[option_idx].name' was given, with argument
             * `optarg'. */
            break;
        case 'h':
            usage(argv[0], EXIT_SUCCESS);
        case 'N':
            args->dont_daemonize = 1;
            break;
        case '?': /* Fall through. */
        default:
            usage(argv[0], EXIT_FAILURE);
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
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    frame_chunk__pack(&fchunk, packed_buf);

    /* Write packed protocol buffer to file. */
    if (write(fd, packed_buf, packed_size) == -1) {
        perror("write");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    struct arguments args;
    const char out_path[] = "/tmp/fchunk-wire-fmt";

    parse_args(&args, argc, argv);

    printf("Writing protobuf to %s.\n", out_path);

    /* Leave stderr open for now, so we can perror() after calling
     * daemonize().
     * TODO: remove this once we've got a proper logging system. */
    fd_set leave_open;
    FD_ZERO(&leave_open);
    FD_SET(STDERR_FILENO, &leave_open);

    /* Become a daemon. */
    if (!args.dont_daemonize && (daemonize(&leave_open, 0) == -1)) {
        perror("daemonize");
        exit(EXIT_FAILURE);
    }

    /* Write to out_path. */
    int out_fd = open(out_path, O_RDWR | O_CREAT, 0644);
    if (out_fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    write_fchunk_to(out_fd);
    close(out_fd);
    return 0;
}
