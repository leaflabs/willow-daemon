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

#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <signal.h>
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
#include "control.h"
#include "hdf5_ch_storage.h"
#include "raw_ch_storage.h"

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

/* Ports to listen on for client and data node control connections. */
#define DNODE_CC_PORT 8880
#define CLIENT_CC_PORT 8881

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

//////////////////////////////////////////////////////////////////////

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

//////////////////////////////////////////////////////////////////////

static void
sigint_handler(__unused int signum, __unused short what, void *basevp)
{
    log_INFO("caught SIGINT");
    event_base_loopbreak((struct event_base*)basevp);
}

static void
sigterm_handler(__unused int signum, __unused short what, void *basevp)
{
    log_INFO("caught SIGTERM");
    event_base_loopbreak((struct event_base*)basevp);
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

static int
run_event_loop(__unused struct ch_storage *chstorage)
{
    int ret = EXIT_FAILURE;
    struct event_base *base = event_base_new();
    if (!base) {
        log_EMERG("can't get event loop");
        goto nobase;
    }
    struct event *ev_sigint = evsignal_new(base, SIGINT, sigint_handler, base);
    if (!ev_sigint) {
        log_EMERG("can't get SIGINT handler");
        goto nosigint;
    }
    struct event *ev_sigterm = evsignal_new(base, SIGTERM, sigterm_handler,
                                            base);
    if (!ev_sigterm) {
        log_EMERG("can't get SIGTERM handler");
        goto nosigterm;
    }
    if (event_add(ev_sigint, NULL) || event_add(ev_sigterm, NULL)) {
        log_EMERG("can't install signal handlers");
        goto nosiginstall;
    }
    struct control_session *control = control_new(base, CLIENT_CC_PORT,
                                                  DNODE_CC_PORT);
    if (!control) {
        log_EMERG("can't create control session");
        goto nocontrol;
    }

    switch (event_base_dispatch(base)) {
    case 0:
        ret = EXIT_SUCCESS;
        break;
    case 1:
        /* This is a bug; signal handlers should persist: */
        log_DEBUG("no more pending events!");
        /* Fall through. */
    default:
        ret = EXIT_FAILURE;
        break;
    }

    control_free(control);
 nocontrol:
 nosiginstall:
    event_free(ev_sigterm);
 nosigterm:
    event_free(ev_sigint);
 nosigint:
    event_base_free(base);
 nobase:
    return ret;
}

static int daemon_main()
{
    int ret = EXIT_FAILURE;
    struct ch_storage *chstorage = alloc_ch_storage();
    if (!chstorage) {
        log_CRIT("can't allocate channel storage object");
        goto nochstorage;
    }
    if (ch_storage_open(chstorage) == -1) {
        log_CRIT("can't open channel storage: %m");
        goto noopen;
    }

    /*
     * Everything happens in the event loop.
     */
    ret = run_event_loop(chstorage);

    ch_storage_close(chstorage);
 noopen:
    free_ch_storage(chstorage);
 nochstorage:
    return ret;
}

//////////////////////////////////////////////////////////////////////

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
        log_EMERG("evthread_use_pthreads() failed");
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
    log_DEBUG("pid: %d, client port: %d, dnode port: %d",
              getpid(), CLIENT_CC_PORT, DNODE_CC_PORT);
    ret = daemon_main();
 bail:
    logging_fini();
    exit(ret);
}
