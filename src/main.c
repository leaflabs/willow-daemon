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

#include <event2/event.h>
#include <event2/thread.h>

#include "daemon.h"
#include "logging.h"
#include "sockutil.h"
#include "type_attrs.h"
#include "raw_packets.h"

#include "ch_storage.h"
#include "hdf5_ch_storage.h"
#include "raw_ch_storage.h"
#include "data_node.h"

/* libevent log levels with leading underscores are deprecated as of
 * libevent 2.0.19. That's not available yet in some popular Linux
 * distros at time of writing, so here are backwards-compatibility
 * defines. Remove them when they're ancient. */
#ifndef EVENT_LOG_DEBUG
#define EVENT_LOG_DEBUG _EVENT_LOG_DEBUG
#endif
#ifndef EVENT_LOG_MSG
#define EVENT_LOG_MSG _EVENT_LOG_MSG
#endif
#ifndef EVENT_LOG_WARN
#define EVENT_LOG_WARN _EVENT_LOG_WARN
#endif
#ifndef EVENT_LOG_ERR
#define EVENT_LOG_ERR _EVENT_LOG_ERR
#endif

/* main() initializes this before doing anything else. */
static const char* program_name;

/* Data node's hostname and command/control port, and local packet
 * data port. */
#define DNODE_HOST "127.0.0.1"
#define DNODE_CC_PORT 8880
#define DNODE_DT_PORT 8881

/* Whether to store data into HDF5 (==1) or just do raw write() (==0;
 * for benchmarking). */
#define DO_HDF5_STORAGE 0

/* Local file to start storing in. This gets truncated each time you
 * run the daemon. */
#define DNODE_DATA_DIR "/tmp"
#if DO_HDF5_STORAGE
#define DNODE_DATA_FILE DNODE_DATA_DIR "/dnode_data.h5"
#else
#define DNODE_DATA_FILE DNODE_DATA_DIR "/dnode_data.raw"
#endif
#define DNODE_DATASET_NAME "ANONYMOUS_DATASET"

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

static struct ch_storage* alloc_ch_storage(void)
{
    struct ch_storage *chns;
    if (DO_HDF5_STORAGE) {
        chns = hdf5_ch_storage_alloc(DNODE_DATA_FILE, DNODE_DATASET_NAME);
    } else {
        chns = raw_ch_storage_alloc(DNODE_DATA_FILE,
                                    O_CREAT | O_RDWR | O_TRUNC, 0644);
    }
    return chns;
}

static void free_ch_storage(struct ch_storage* chns)
{
    if (DO_HDF5_STORAGE) {
        hdf5_ch_storage_free(chns);
    } else  {
        raw_ch_storage_free(chns);
    }
}

static int open_dnode_sockets(struct dnode_session *dnsession)
{
    dnsession->cc_sock = sockutil_get_tcp_connected_p(DNODE_HOST,
                                                      DNODE_CC_PORT);
    dnsession->dt_sock = sockutil_get_udp_socket(DNODE_DT_PORT);
    return (dnsession->cc_sock == -1 || dnsession->dt_sock == -1) ? -1 : 0;
}

static int run_event_loop(__unused struct dnode_session *dnsession)
{
    log_WARNING("%s: unimplemented", __func__);
    return EXIT_FAILURE;
}

static int daemon_main()
{
    int ret = EXIT_FAILURE;
    int cs_is_open = 0;

    /*
     * Datanode and client session state.
     */
    struct raw_pkt_cmd request_packet;
    raw_packet_init(&request_packet, RAW_MTYPE_REQ, 0);
    raw_req(&request_packet)->r_id = 0;
    struct raw_pkt_cmd response_packet;
    raw_packet_init(&response_packet, RAW_MTYPE_RES, 0);
    const struct timespec timeout = {
        .tv_sec = 0,
        .tv_nsec = 100 * 1000 * 1000, /* 100 msec */
    };
    struct dnode_session dn_session = {
        .cc_sock = -1,
        .dt_sock = -1,
        .req = &request_packet,
        .res = &response_packet,
        .chns = NULL,
        .pkt_recv_timeout = &timeout,
    };
    /* Set up channel storage */
    dn_session.chns = alloc_ch_storage();
    if (!dn_session.chns) {
        log_ERR("can't allocate channel storage object");
        goto bail;
    }
    cs_is_open = ch_storage_open(dn_session.chns) != -1;
    if (!cs_is_open) {
        log_ERR("can't open channel storage: %m");
        goto bail;
    }
    /* Open connection to data node. */
    if (open_dnode_sockets(&dn_session) == -1) {
        log_ERR("can't connect to data node at %s port %d: %m",
                DNODE_HOST, DNODE_CC_PORT);
        goto bail;
    }

    /*
     * Everything happens in the event loop.
     */
    ret = run_event_loop(&dn_session);

 bail:
    if (ret == EXIT_FAILURE) {
        log_ERR("exiting due to error");
    }
    if (dn_session.dt_sock != -1 && close(dn_session.dt_sock) != 0) {
        log_ERR("unable to close data socket: %m");
    }
    if (dn_session.cc_sock != -1 && close(dn_session.cc_sock) != 0) {
        log_ERR("unable to close command/control socket: %m");
    }
    if (dn_session.chns) {
        if (cs_is_open && ch_storage_close(dn_session.chns) == -1) {
            log_ERR("unable to close channel storage: %m");
        }
        free_ch_storage(dn_session.chns);
    }
    return ret;
}

static void libevent_log_cb(int severity, const char *msg)
{
#define LE_LOG_FMT "libevent: %s"
    switch (severity) {
    case EVENT_LOG_DEBUG: log_DEBUG(LE_LOG_FMT, msg);   break;
    case EVENT_LOG_MSG:   log_INFO(LE_LOG_FMT, msg);    break;
    case EVENT_LOG_WARN:  log_WARNING(LE_LOG_FMT, msg); break;
    case EVENT_LOG_ERR:   log_ERR(LE_LOG_FMT, msg);     break;
    default:
        log_ERR("[unknown libevent severity %d]: %s", severity, msg);
        break;
    }
#undef LE_LOG_FMT
}

static void libevent_fatal_error_cb(int err)
{
    log_EMERG("fatal libevent error %d", err);
    exit(1);
}

static int setup_libevent(void) /* Before daemonizing */
{
    event_set_log_callback(libevent_log_cb);
    event_set_fatal_callback(libevent_fatal_error_cb);
    if (evthread_use_pthreads() == -1) {
        log_ERR("evthread_use_pthreads() failed");
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    struct arguments args = DEFAULT_ARGUMENTS;
    int ret = EXIT_FAILURE;

    /* Stash the program name, parse arguments, and set up logging and
     * libevent before doing anything else.
     *
     * AFTER THIS POINT, DO NOT USE printf() etc.; use the logging.h
     * API instead. */
    program_name = strdup(argv[0]);
    if (!program_name) {
        fprintf(stderr, "Out of memory at startup\n");
        goto bail;
    }
    parse_args(&args, argc, argv);
    int log_to_stderr = args.dont_daemonize;
    logging_init(program_name, LOG_DEBUG, log_to_stderr);
    if (setup_libevent()) {
        goto bail;
    }

    /* Become a daemon. */
    fd_set leave_open;
    FD_ZERO(&leave_open);
    if (!args.dont_daemonize && (daemonize(&leave_open, 0) == -1)) {
        log_EMERG("can't daemonize: %m");
        goto bail;
    }

    /* Go! */
    ret = daemon_main();
 bail:
    logging_fini();
    exit(ret);
}
