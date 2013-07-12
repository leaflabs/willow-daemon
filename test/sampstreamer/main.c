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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "raw_packets.h"
#include "sockutil.h"

#define PROGRAM_NAME "sampstreamer"
#define FROM_PORT 5678
#define DAEMON_PORT 1370

static void usage(int exit_status)
{
    printf("Usage: %s [-p <port>] [-h]\n"
           "Options:\n"
           "  -f, --from-port\n"
           "\tSend to daemon from this localhost port, default %d\n"
           "  -h, --help"
           "\tPrint this message\n"
           "  -p, --port"
           "\tSend to daemon at this localhost port, default %d\n"
           "  -s, --subs"
           "\tSend board subsamples instead of full board samples\n"
           ,
           PROGRAM_NAME, FROM_PORT, DAEMON_PORT);
    exit(exit_status);
}

#define DEFAULT_ARGUMENTS                               \
    {  .from_port = 5678, .daemon_port = DAEMON_PORT, .subsamples = 0, }

struct arguments {
    uint16_t from_port;
    uint16_t daemon_port;
    int subsamples;
};

static void parse_args(struct arguments* args, int argc, char *const argv[])
{
    int print_usage = 0;
    const char shortopts[] = "f:hp:s";
    struct option longopts[] = {
        /* Keep these sorted with shortopts. */
        { .name = "from-port",
          .has_arg = required_argument,
          .flag = &print_usage,
          .val = 'f' },
        { .name = "help",
          .has_arg = no_argument,
          .flag = NULL,
          .val = 'h' },
        { .name = "port",
          .has_arg = required_argument,
          .flag = &print_usage,
          .val = 'p' },
        { .name = "subs",
          .has_arg = no_argument,
          .flag = NULL,
          .val = 's' },
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
        case 'f':
            args->from_port = strtol(optarg, (char**)0, 10);
            break;
        case 'h':
            usage(EXIT_SUCCESS);
            break;
        case 'p':
            args->daemon_port = strtol(optarg, (char**)0, 10);
            break;
        case 's':
            args->subsamples = 1;
            break;
        case '?': /* Fall through. */
        default:
            usage(EXIT_FAILURE);
        }
    }
}

#define USLEEP_TIME 1
#define COOKIE_H 0xDEADBEEF
#define COOKIE_L 0xDEADBEEF
#define BOARD_ID 1234
#define START_INDEX 0
#define CHIPS_LIVE 0xFFFFFFFF

static inline void send_pkt(void *pkt, size_t size, int sockfd,
                            struct sockaddr_in *to)
{
    ssize_t status = sendto(sockfd, pkt, size, MSG_NOSIGNAL, to, sizeof(*to));
    if (status < 0) {
        perror("sendto");
    }
    if ((size_t)status != size) {
        fprintf(stderr, "bad packet send length: wanted %zu, got %zd",
                size, status);
    }
    usleep(USLEEP_TIME);
}

void send_subsamples(int sockfd, struct sockaddr_in *to)
{
    struct raw_pkt_bsub bsub;
    uint8_t dac = 0;
    uint32_t idx = START_INDEX;
    do {
        raw_packet_init(&bsub, RAW_MTYPE_BSUB, 0);
        bsub.b_cookie_h = COOKIE_H;
        bsub.b_cookie_l = COOKIE_L;
        bsub.b_id = BOARD_ID;
        bsub.b_sidx = idx++;
        bsub.b_dac = dac++;
        bsub.b_chip_live = CHIPS_LIVE;
        if (raw_pkt_hton(&bsub)) {
            fprintf(stderr, "invalid packet\n");
            exit(EXIT_FAILURE);
        }
        send_pkt(&bsub, sizeof(bsub), sockfd, to);
    } while (1);
}

void send_samples(int sockfd, struct sockaddr_in *to)
{
    struct raw_pkt_bsmp bsmp;
    uint32_t idx = START_INDEX;
    do {
        raw_packet_init(&bsmp, RAW_MTYPE_BSMP, 0);
        bsmp.b_cookie_h = COOKIE_H;
        bsmp.b_cookie_l = COOKIE_L;
        bsmp.b_id = BOARD_ID;
        bsmp.b_sidx = idx++;
        bsmp.b_chip_live = CHIPS_LIVE;
        if (raw_pkt_hton(&bsmp)) {
            fprintf(stderr, "invalid packet\n");
            exit(EXIT_FAILURE);
        }
        send_pkt(&bsmp, sizeof(bsmp), sockfd, to);
    } while (1);
}

int main(int argc, char *argv[])
{
    struct arguments args = DEFAULT_ARGUMENTS;

    parse_args(&args, argc, argv);

    fprintf(stderr, "from_port=%u, daemon port=%u\n",
            args.from_port, args.daemon_port);

    int sockfd = sockutil_get_udp_socket(args.from_port);
    if (sockfd == -1) {
        perror("sockutil_get_udp_socket");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in to = {
        .sin_addr.s_addr = htonl(0x7f000001),
        .sin_port = htons(args.daemon_port),
    };

    if (args.subsamples) {
        send_subsamples(sockfd, &to);
    } else {
        send_samples(sockfd, &to);
    }

    exit(EXIT_SUCCESS);         /* placate compiler */
}
