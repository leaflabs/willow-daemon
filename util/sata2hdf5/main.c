/* Copyright (c) 2013 LeafLabs, LLC.
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * sata2hdf5
 *
 *  Utility to read raw board samples from a bare block device (eg, a SATA disk
 *  attached via a USB 3.0 adapter and available at /dev/sd{b,c,d,...}) and
 *  copy out to an HDF5 file for later analysis or archiving.
 *
 *  The motivation for this utility is that reading back long experimental
 *  sessions from a data node over the gigabit ethernet interface is limited to
 *  gigabit speeds at best (~80 MB/sec) and as of September 2013 is a factor of
 *  3x slower in practice. For fast SSDs, the theoretical througput is closer
 *  to 100-200 MB/sec (though HDF5 serialization will increasingly become a
 *  bottleneck).
 *
 *  Other use cases for this utility are to recover data from old disks and to
 *  allow for rapid re-use of data nodes for new experiments without first
 *  archiving data from previous experiments.
 *
 *  Performance is a bit better than real-time reading from a raw SSD via USB
 *  3.0 and writing to an encrypted SSD filesystem (52.5 seconds to copy 1.8
 *  million samples == 60 second experiment == 3.8 GB). Performance is a bit
 *  better copying the same data from the filesystem disk to the filesystem
 *  disk (42.0 seconds).
 */

/*
 * NEEDS REVIEW:
 *  - add _FILE_OFFSET_BITS 64 for huge files? (>4GB)
 *  - are file errors caught and handled correctly?
 *  - best practice for declaring unsigned 64bit numbers?
 */


#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "raw_packets.h"
#include "sockutil.h"
#include "proto/data.pb-c.h"
#include "hdf5_ch_storage.h"
#include "ch_storage.h"

#define PROGRAM_NAME "sata2hdf5"
#define MAX_LENGTH_SECTORS 8
#define MIN_LENGTH_SECTORS 5
#define DEFAULT_LENGTH_SECTORS MAX_LENGTH_SECTORS
#define BUF_LEN (512 * MAX_LENGTH_SECTORS)

static void usage(int exit_status)
{
    fprintf(exit_status == EXIT_SUCCESS ? stdout : stderr,
            "Usage: %s  [-c <count>] [-l <sectors>] [-o <offset>] <inpath> "
            "<outpath>\n"
            "Options:\n"
            "  -c, --count"
            "\thow many board samples to save; defaults to end-of-experiment\n"
            "  -l, --length"
            "\tNumber of 512 byte sectors per board sample, default %d\n"
            "  -o, --offset"
            "\tboard sample index to start at; default to 0\n"
            "  -h, --help"
            "\tPrint this message\n"
            ,
            PROGRAM_NAME, DEFAULT_LENGTH_SECTORS);
    exit(exit_status);
}

#define DEFAULT_ARGUMENTS               \
    { .count = 0,                       \
      .length = DEFAULT_LENGTH_SECTORS,     \
      .offset = 0,                      \
    }

struct arguments {
    unsigned long int count;
    unsigned int length;
    unsigned long int offset;
    char * inpath;
    char * outpath;
};

static void parse_args(struct arguments* args, int argc, char *const argv[])
{
    int print_usage = 0;
    const char shortopts[] = "c:hl:o:";
    struct option longopts[] = {
        /* Keep these sorted with shortopts. */
        { .name = "count",
          .has_arg = required_argument,
          .flag = NULL,
          .val = 'c' },
        { .name = "help",
          .has_arg = no_argument,
          .flag = NULL,
          .val = 'h' },
        { .name = "length",
          .has_arg = required_argument,
          .flag = NULL,
          .val = 'l' },
        { .name = "offset",
          .has_arg = required_argument,
          .flag = NULL,
          .val = 'o' },
        {0, 0, 0, 0},
    };
    long int count;
    int length;
    long int offset;
    /* TODO add error handling in strtol() argument conversion */
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
        case 'c':
            count = strtol(optarg, (char**)0, 10);
            if (count < 0) {
                fprintf(stderr, "count %ld must be positive\n", count);
                usage(EXIT_FAILURE);
            }
            args->count = (unsigned long int)count;
            break;
        case 'l':
            length = strtol(optarg, (char**)0, 10);
            if (length < 0) {
                fprintf(stderr, "length %d must be positive\n", length);
                usage(EXIT_FAILURE);
            }
            args->length = (unsigned int)length;
            break;
        case 'o':
            offset = strtol(optarg, (char**)0, 10);
            if (count < 0) {
                fprintf(stderr, "offset %ld must be positive\n", offset);
                usage(EXIT_FAILURE);
            }
            args->offset= (unsigned long int)offset;
            break;
        case 'h':
            usage(EXIT_SUCCESS);
            break;
        case '?': /* Fall through. */
        default:
            usage(EXIT_FAILURE);
        }
    }
    if (args->length > MAX_LENGTH_SECTORS ||
        args->length < MIN_LENGTH_SECTORS) {
        fprintf(stderr,
                "sector length must be <= %d and >= %d\n",
                MAX_LENGTH_SECTORS,
                MIN_LENGTH_SECTORS);
        usage(EXIT_FAILURE);
    }
    if ((argc - optind) != 2) {
        fprintf(stderr, "missing inpath or outpath arguments\n");
        usage(EXIT_FAILURE);
    }
    args->inpath = argv[optind++];
    args->outpath = argv[optind++];
}

int main(int argc, char *argv[])
{
    struct arguments args = DEFAULT_ARGUMENTS;

    /* Hackish here; lots of overlapping memory and pointers.
     *
     * We are re-using library code that expect board sample packets, not raw
     * board samples. Packets are just board samples with a 4 byte header
     * tacked on. Instead of copying or converting from raw samples to packets,
     * we initialize a proper raw sample packet at the begining of a long byte
     * buffer, read raw binary data into the buffer at a 4-byte offset, and
     * then pass the buf_pkt_bsmp pointer (to the very begining of the buffer)
     * to the HDF5 writing routines.
     *
     * The buffer is larger than a raw_pkt_bsmp because it is also used to
     * strip out padding sectors. We don't know yet how many sectors to strip
     * (this is a command-line argument), so we allocate a worst-case size
     * buffer.
     */
    uint8_t buf[sizeof(struct raw_pkt_header) + BUF_LEN];
    struct raw_pkt_bsmp* buf_pkt_bsmp = (void*)buf;
    if (sizeof(buf) <= sizeof(buf_pkt_bsmp)) {
        fprintf(stderr, "FAIL.\n");
        exit(-1);
    }

    raw_packet_init(buf_pkt_bsmp, RAW_MTYPE_BSMP, 0);

/* DEBUG
    printf("buf_pkt_bsmp.p_mtype: %d\n", buf_pkt_bsmp->ph.p_mtype);

    printf("buf: %p\n", buf);
    printf("len buf: %d\n", (int)sizeof(struct raw_pkt_header) + BUF_LEN);
    printf("buf + 4: %p\n", buf+4);
    printf("raw_pkt_bsmp: %p\n", buf_pkt_bsmp);
    printf("raw_pkt_bsmp + sizeof(struct raw_pkt_header)): %p\n",
        buf_pkt_bsmp + sizeof(struct raw_pkt_header));
    printf("raw_pkt_bsmp + 4: %p\n", buf_pkt_bsmp + 4);
    printf("sizeof(struct raw_pkt_bsmp): %d\n",
           (int)sizeof(struct raw_pkt_bsmp));
    printf("sizeof(struct raw_pkt_header): %d\n",
           (int)sizeof(struct raw_pkt_header));
*/

    parse_args(&args, argc, argv);
/* DEBUG
    printf("========= Args:\n");
    printf("Count: %ld\n", args.count);
    printf("Length: %d sectors\n", args.length);
    printf("Offset: %ld\n", args.offset);
*/

    FILE * infile = fopen(args.inpath, "rb");
    if (NULL == infile) {
        fprintf(stderr, "couldn't open input file for reading: ");
        fprintf(stderr, "%s\n", args.inpath);
        exit(EXIT_FAILURE);
    }
    struct ch_storage* chns = hdf5_ch_storage_alloc(
        args.outpath, "wired-dataset");
    int status = ch_storage_open(chns, H5F_ACC_TRUNC);
    if (status != 0) {
        fprintf(stderr, "couldn't open output file for writing: ");
        fprintf(stderr, "%s\n", args.outpath);
        fclose(infile);
        exit(EXIT_FAILURE);
    }

    int len;
    long int fptr = args.offset * args.length * 512;
    unsigned long int count = 0;
    uint64_t cookie, this_cookie;
    uint32_t bsi = args.offset;
    uint32_t board_id;
    // DEBUG printf("========= Starting...\n");
    while (1) {
        fseek(infile, fptr, SEEK_SET);
        len = fread(buf + sizeof(struct raw_pkt_header), 1,
                    512*args.length, infile);
        if (len != (int)(512*args.length)) {
            if (ferror(infile)) {
                if (ferror(infile) == EFAULT) {
                    fprintf(stderr, "Problem allocating memory?\n");
                }
                perror("Error reading");
            } else if (!feof(infile)) {
                printf("got short data, bailing\n");
            } else if (args.count && args.count != count) {
                printf("reached EOF prematurely, bailing\n");
            }
            break;
        }

        // fix byte ordering
        raw_pkt_hton(buf_pkt_bsmp);

        // (pseudo) validate packet
        this_cookie = ((uint64_t)buf_pkt_bsmp->b_cookie_h << 32) \
                      | (uint64_t)buf_pkt_bsmp->b_cookie_l;
        if (0 == count) {
            cookie = this_cookie;
            printf("Starting cookie: 0x%lx\n", cookie);
        } else if (cookie != this_cookie) {
            printf("Experiment number changed (0x%lx != 0x%lx), bailing.\n",
                   this_cookie, cookie);
            break;
        }
        if (buf_pkt_bsmp->b_sidx != bsi) {
            printf("Unexpected board sample index (%d != %d), bailing.\n",
                   buf_pkt_bsmp->b_sidx, bsi);
            break;
        } else {
            bsi++;
        }
        if (0 == count) {
            board_id = buf_pkt_bsmp->b_id;
            printf("Starting board id: 0x%x\n", board_id);
        } else if (buf_pkt_bsmp->b_id != board_id) {
            printf("Unexpected board id (0x%x != 0x%x), bailing.\n",
                buf_pkt_bsmp->b_id, board_id);
            break;
        }

        // write hdf5 sample
        len = ch_storage_write(chns, buf_pkt_bsmp, 1);

        // increment file pointer by <length> sectors
        fptr += args.length * 512;
        count++;

        // print progress every ~second of copied data
        if (!(count % 30000)) {
            printf("Copied %ld...\n", count);
        }
        // check loop condition
        if (args.count > 0 && args.count == count) break;
    }

/* TODO: enable disk synchronization? could speculatively make batch jobs run
 * slowly, so commented out.

    printf("Synchronizing disk...\n");
    fsync(fileno(infile));
*/

    // Close infile first in case there are problems cleaning up ch_storage
    fclose(infile);
    ch_storage_close(chns);
    ch_storage_free(chns);

    // DEBUG printf("========= Done.\n");
    printf("Copied %ld board samples.\n", count);
    exit(EXIT_SUCCESS);         /* placate compiler */
}
