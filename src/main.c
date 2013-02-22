/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/select.h>

#include "daemon.h"
#include "proto/open-ephys.pb-c.h"

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
    const char out_path[] = "/tmp/fchunk-wire-fmt";

    /* Leave stderr open for now, so we can perror() after calling
     * daemonize().
     * TODO: remove this once we've got a proper logging system. */
    fd_set leave_open;
    FD_ZERO(&leave_open);
    FD_SET(STDERR_FILENO, &leave_open);

    printf("Becoming daemon, then writing protobuf to %s.\n", out_path);

    /* Become a daemon. */
    if (daemonize(&leave_open, 0) == -1) {
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
