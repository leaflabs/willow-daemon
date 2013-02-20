#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "proto/open-ephys.pb-c.h"

int main(int argc, char *argv[])
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

    /* Write packed protocol buffer to stdout. */
    fwrite(packed_buf, packed_size, 1, stdout);

    return 0;
}
