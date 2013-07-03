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

#include <net/if.h>
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
#include "sample.h"

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

/* Default network configuration. */
#define DAEMON_CLIENT_PORT 1371 /* client control sockets connect to here */
#define DAEMON_SAMPLE_IFACE "eth0"
#define DAEMON_SAMPLE_PORT 1370 /* daemon receive board subsamples here */
#define DUMMY_DNODE_ADDRESS "127.0.0.1" /* for dummy-datanode debugging */
#define DNODE_LISTEN_PORT  1369 /* data node listens for connections here */

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

static void panic(const char *msg)
{
    fprintf(stderr, "%s: %s\n", program_name, msg);
    _exit(EXIT_FAILURE);
}

static void usage(int exit_status)
{
    printf("Usage: %s\n"
           "Options:\n"
           "  -A, --dnode-address"
           "\tConnect to data node at this address, default %s\n"
           "  -c, --client-port"
           "\tListen here for client control socket connections, default %d\n"
           "  -d, --dnode-port"
           "\tConnect to data node on this port, default %d\n"
           "  -h, --help"
           "\t\tPrint this message and quit\n"
           "  -I, --sample-iface"
           "\tNetwork interface to receive samples on, default %s\n"
           "  -N, --dont-daemonize"
           "\tSkip daemonization; logs also go to stderr\n"
           "  -s, --sample-port"
           "\tCreate data node data socket here, default %d\n",
           program_name, DUMMY_DNODE_ADDRESS, DAEMON_CLIENT_PORT,
           DNODE_LISTEN_PORT, DAEMON_SAMPLE_IFACE, DAEMON_SAMPLE_PORT);
    exit(exit_status);
}

#define DEFAULT_ARGUMENTS                                       \
        { .client_port = DAEMON_CLIENT_PORT,                    \
          .dnode_addr = DUMMY_DNODE_ADDRESS,                    \
          .dnode_port = DNODE_LISTEN_PORT,                      \
          .sample_iface = DAEMON_SAMPLE_IFACE,                  \
          .sample_port = DAEMON_SAMPLE_PORT,                    \
          .dont_daemonize = 0,                                  \
        }

struct arguments {
    uint16_t  client_port;      /* Listen for clients here */
    char     *dnode_addr;       /* Connect to dnode at this address */
    uint16_t  dnode_port;       /* Connect to dnode at this port */
    char     *sample_iface;     /* Use this interface to receive samples */
    uint16_t  sample_port;      /* Receive dnode samples here */
    int       dont_daemonize;   /* Skip daemonization. */
};

static void parse_args(struct arguments* args, int argc, char *const argv[])
{
    int print_usage = 0;
    const char shortopts[] = "A:c:d:hI:Ns:";
    struct option longopts[] = {
        /* Keep these sorted with shortopts. */
        { .name = "dnode-address", /* -A */
          .has_arg = required_argument,
          .flag = NULL,
          .val = 'A' },
        { .name = "client-port", /* -c */
          .has_arg = required_argument,
          .flag = NULL,
          .val = 'c' },
        { .name = "dnode-port", /* -d */
          .has_arg = required_argument,
          .flag = NULL,
          .val = 'd' },
        { .name = "help",       /* -h */
          .has_arg = no_argument,
          .flag = &print_usage,
          .val = 1 },
        { .name = "sample-iface",   /* -I */
          .has_arg = required_argument,
          .flag = NULL,
          .val = 'I' },
        { .name = "dont-daemonize", /* -N */
          .has_arg = no_argument,
          .flag = &args->dont_daemonize,
          .val = 1 },
        { .name = "sample-port", /* -s */
          .has_arg = required_argument,
          .flag = NULL,
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
            args->dnode_addr = strdup(optarg);
            if (!args->dnode_addr) {
                panic("out of memory");
            }
            break;
        case 'c':
            args->client_port = strtol(optarg, (char**)0, 10);
            break;
        case 'd':
            args->dnode_port = strtol(optarg, (char**)0, 10);
            break;
        case 'h':
            usage(EXIT_SUCCESS);
        case 'I':
            args->sample_iface = optarg;
            break;
        case 'N':
            args->dont_daemonize = 1;
            break;
        case 's':
            args->sample_port = strtol(optarg, (char**)0, 10);
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
        chns = raw_ch_storage_alloc(DNODE_DATA_FILE, 0644);
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
run_event_loop(struct arguments *args,
               struct ch_storage *chstorage)
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
    unsigned iface = if_nametoindex(args->sample_iface);
    if (iface == 0) {
        log_EMERG("unknown network interface %s", args->sample_iface);
    }
    struct sample_session *sample = sample_new(base, iface, args->sample_port,
                                               chstorage);
    if (!sample) {
        log_EMERG("can't create sample session, iface %u, port %u",
                  iface, args->sample_port);
        goto nosample;
    }
    struct control_session *control = control_new(base, args->client_port,
                                                  args->dnode_addr,
                                                  args->dnode_port,
                                                  sample);
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
    sample_free(sample);
 nosample:
 nosiginstall:
    event_free(ev_sigterm);
 nosigterm:
    event_free(ev_sigint);
 nosigint:
    event_base_free(base);
 nobase:
    return ret;
}

static int daemon_main(struct arguments *args)
{
    int ret = EXIT_FAILURE;
    struct ch_storage *chstorage = alloc_ch_storage();
    if (!chstorage) {
        log_CRIT("can't allocate channel storage object");
        goto nochstorage;
    }
    unsigned flags = DO_HDF5_STORAGE ?
        H5F_ACC_TRUNC :
        O_CREAT | O_RDWR | O_TRUNC;
    if (ch_storage_open(chstorage, flags) == -1) {
        log_CRIT("can't open channel storage: %m");
        goto noopen;
    }

    /*
     * Everything happens in the event loop.
     */
    ret = run_event_loop(args, chstorage);

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

/* Per-stack-entry HDF5 logging callback. Prints a message for a
 * single element of the error stack. */
static herr_t hdf5_logger(unsigned n, const H5E_error2_t *ep,
                          __unused void *ignored)
{
    herr_t ret = 0;
    char class[LINE_MAX] = {[0] = '\0'};
    char major[LINE_MAX] = {[0] = '\0'};
    char minor[LINE_MAX] = {[0] = '\0'};

    if (H5Eget_class_name(ep->cls_id, class, sizeof(class)) < 0) {
        log_ERR("HDF5[%u]: can't get name for class %llu",
                n, (long long unsigned)ep->cls_id);
        ret = -1;
    }
    if (H5Eget_msg(ep->maj_num, NULL, major, sizeof(major)) < 0) {
        log_ERR("HDF5[%u]: can't get string for major %llu",
                n, (long long unsigned)ep->maj_num);
        ret = -1;
    }
    if (H5Eget_msg(ep->min_num, NULL, minor, sizeof(minor)) < 0) {
        log_ERR("HDF5[%u]: can't get string for minor %llu",
                n, (long long unsigned)ep->min_num);
        ret = -1;
    }

    log_ERR("HDF5[%u]: %s:%u:%s(): %s (class %s, major/minor %s/%s)",
            n, ep->file_name, ep->line, ep->func_name, ep->desc,
            class, major, minor);
    return ret;
}

/* Top-level HDF5 callback. Walk the error stack, printing an error
 * record at each level with hdf5_logger(). */
static herr_t hdf5_log_cb(hid_t estack, void *arg)
{
    return H5Ewalk2(estack, H5E_WALK_DOWNWARD, hdf5_logger, arg);
}

static herr_t setup_hdf5(void)
{
    return H5Eset_auto2(H5E_DEFAULT, hdf5_log_cb, NULL);
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
    if (setup_hdf5() < 0) {
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
    log_DEBUG("pid: %d, client port: %u, dnodeaddr: %s, dnode port: %u, "
              "sample iface=%s, sample port: %u",
              getpid(), args.client_port, args.dnode_addr, args.dnode_port,
              args.sample_iface, args.sample_port);
    ret = daemon_main(&args);
 bail:
    logging_fini();
    exit(ret);
}
