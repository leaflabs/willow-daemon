#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "raw_packets.h"
#include "sockutil.h"
#include "proto/data.pb-c.h"

#define PROGRAM_NAME "proto2bytes"
#define DAEMON_PORT 7654

enum out_type {
    OUT_CHANNEL,
    OUT_DAC,
};

static const char* out_type_str(enum out_type type)
{
    switch (type) {
    case OUT_CHANNEL: return "channel";
    case OUT_DAC: return "dac";
    default: return "<UNKNOWN out_type>";
    }
}

static void usage(int exit_status)
{
    fprintf(exit_status == EXIT_SUCCESS ? stdout : stderr,
            "Usage: %s [-d|-c <ch>] [-p <port>] [-s]\n"
            "Options:\n"
            "  -A, --all-sub"
            "\tOutput all 32 channels. Implies subsamples.\n"
            "  -c, --channel"
            "\t(16-bit) channel to output\n"
            "  -d, --dac"
            "\tOutput DAC channel (this is the default)\n"
            "  -h, --help"
            "\tPrint this message\n"
            "  -M, --board-samples"
            "\tExpect board samples instead of subsamples\n"
            "  -p, --port"
            "\tListen to daemon at this address, default %d\n"
            "  -s, --string"
            "\tOutput values as strings on stdout instead of bytes\n"
            ,
            PROGRAM_NAME, DAEMON_PORT);
    exit(exit_status);
}

#define DEFAULT_ARGUMENTS          \
    { .daemon_port = DAEMON_PORT,  \
      .output = OUT_DAC,           \
      .channel = -1,               \
      .enable_string = 0,          \
      .board_samples = 0,          \
      .all_sub_channels = 0,       \
    }

struct arguments {
    uint16_t daemon_port;
    enum out_type output;
    unsigned channel;
    int enable_string;
    int board_samples;
    int all_sub_channels;
};

static void parse_args(struct arguments* args, int argc, char *const argv[])
{
    int print_usage = 0;
    const char shortopts[] = "Ac:dhMp:s";
    struct option longopts[] = {
        /* Keep these sorted with shortopts. */
        { .name = "all-sub",
          .has_arg = no_argument,
          .flag = NULL,
          .val = 'A' },
        { .name = "channel",
          .has_arg = required_argument,
          .flag = NULL,
          .val = 'c' },
        { .name = "dac",
          .has_arg = no_argument,
          .flag = NULL,
          .val = 'd' },
        { .name = "help",
          .has_arg = no_argument,
          .flag = NULL,
          .val = 'h' },
        { .name = "board-samples",
          .has_arg = no_argument,
          .flag = NULL,
          .val = 'M' },
        { .name = "port",
          .has_arg = required_argument,
          .flag = &print_usage,
          .val = 'p' },
        { .name = "string",
          .has_arg = no_argument,
          .flag = &print_usage,
          .val = 's' },
        {0, 0, 0, 0},
    };
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
        case 'A':
            args->all_sub_channels = 1;
            break;
        case 'c':
            args->output = OUT_CHANNEL;
            int ch = strtol(optarg, (char**)0, 10);
            if (ch < 0) {
                fprintf(stderr, "channel %d must be positive\n", ch);
                usage(EXIT_FAILURE);
            }
            args->channel = (unsigned)ch;
            break;
        case 'd':
            args->output = OUT_DAC;
            break;
        case 'h':
            usage(EXIT_SUCCESS);
            break;
        case 'M':
            args->board_samples = 1;
            break;
        case 'p':
            args->daemon_port = strtol(optarg, (char**)0, 10);
            break;
        case 's':
            args->enable_string = 1;
            break;
        case '?': /* Fall through. */
        default:
            usage(EXIT_FAILURE);
        }
    }
    unsigned max_chan = (args->board_samples ?
                         RAW_BSMP_NSAMP : RAW_BSUB_NSAMP);
    if (args->output == OUT_CHANNEL && args->channel > max_chan) {
        fprintf(stderr, "channel %u is out of range (max is %u)\n",
                args->channel, max_chan);
        exit(EXIT_FAILURE);
    }
    if (args->output == OUT_DAC && args->board_samples) {
        fprintf(stderr, "DAC output for board samples is unimplemented\n");
        exit(EXIT_FAILURE);
    }
    if (args->all_sub_channels && args->board_samples) {
        fprintf(stderr, "all-sub and board-samples are mutually exclusive\n");
        exit(EXIT_FAILURE);
    }
    if (args->all_sub_channels) {
        args->output = OUT_CHANNEL;
    }
}

static void write_chan(uint16_t chan, struct arguments *args)
{
    if (args->enable_string) {
        printf("%u\n", chan);
    } else {
        // NB: only writing the "low" 8bits of sample for waveform
        // display
        uint8_t low = (uint8_t)(chan & 0xFF);
        __unused ssize_t n = write(STDOUT_FILENO, &low, sizeof(low));
    }
}

/* Returns sample index, for gap checking */
uint32_t handle_sample(DnodeSample *samp, struct arguments *args)
{
    /* TODO handle DAC output -- interacts with gap checking */
    assert(args->output == OUT_CHANNEL);

    uint8_t *samples8 = samp->sample->samples.data;
    /* Ensure samples are aligned on a 2-byte boundary before the cast */
    assert(!((uintptr_t)(void*)samples8 & 1));
    uint16_t *samples = (uint16_t*)samples8;
    uint16_t chan = samples[args->channel];
    write_chan(chan, args);
    return samp->sample->samp_idx;
}

/* Returns sample index, for gap checking */
uint32_t handle_subsample(DnodeSample *samp, struct arguments *args)
{
    if (args->output == OUT_DAC) {
        uint8_t dac = (uint8_t)samp->subsample->dac_value;
        if (args->enable_string) {
            printf("%u\n", dac);
        } else {
            __unused ssize_t n = write(STDOUT_FILENO, &dac, sizeof(dac));
        }
    } else if (args->all_sub_channels) {
        if (args->enable_string) {
            for (size_t i = 0; i < samp->subsample->n_samples; i++) {
                printf("%u%s", samp->subsample->samples[i],
                       i < samp->subsample->n_samples - 1 ? "," : "\n");
            }
        } else {
            uint16_t samp16[samp->subsample->n_samples];
            for (size_t i = 0; i < samp->subsample->n_samples; i++) {
                samp16[i] = (uint16_t)(samp->subsample->samples[i] & 0xFFFF);
            }
            size_t s = samp->subsample->n_samples * sizeof(uint16_t);
            __unused ssize_t n = write(STDOUT_FILENO, samp16, s);
        }
    } else {
        uint16_t chan = (uint16_t)samp->subsample->samples[args->channel];
        write_chan(chan, args);
    }
    return samp->subsample->samp_idx;
}

int main(int argc, char *argv[])
{
    uint8_t buf[1024*1024];
    struct arguments args = DEFAULT_ARGUMENTS;

    parse_args(&args, argc, argv);

    char chstr[20];
    snprintf(chstr, sizeof(chstr), "%d", args.channel);
    fprintf(stderr, "daemon port=%u, output field type=%s%s%s\n",
            args.daemon_port, out_type_str(args.output),
            args.output == OUT_CHANNEL ? ", channel=" : "",
            args.output == OUT_CHANNEL ? chstr : "");

    int sockfd = sockutil_get_udp_socket(args.daemon_port);
    if (sockfd == -1) {
        perror("sockutil_get_udp_socket");
        exit(EXIT_FAILURE);
    }

    uint32_t last_sidx = 0;
    while (1) {
        ssize_t n = recvfrom(sockfd, buf, sizeof(buf), 0, NULL, NULL);
        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("recvfrom");
            exit(EXIT_FAILURE);
        }
        DnodeSample *samp = dnode_sample__unpack(NULL, (size_t)n, buf);
        if (!samp) {
            fprintf(stderr, "unpacking failed; skipping packet\n");
            continue;
        }
        if (args.board_samples) {
            if (samp->sample == NULL && samp->subsample) {
                fprintf(stderr, "got subsample, but expected board sample\n");
                continue;
            }
        } else if (samp->subsample == NULL && samp->sample) {
            fprintf(stderr, "got board sample, but expected subsample\n");
            continue;
        }
        uint32_t cur_idx = (args.board_samples ?
                            handle_sample(samp, &args) :
                            handle_subsample(samp, &args));
        uint32_t gap = cur_idx - last_sidx - 1;
        if (gap) {
            fprintf(stderr, "GAP: %d\n", gap);
        }
        last_sidx = cur_idx;
        dnode_sample__free_unpacked(samp, NULL);
    }

    exit(EXIT_SUCCESS);         /* placate compiler */
}
