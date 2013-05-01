/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

/*
 * Dummy datanode, used for system testing the daemon.
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logging.h"
#include "raw_packets.h"
#include "sockutil.h"
#include "type_attrs.h"
#include "chaos.h"

#define DEFAULT_ARGUMENTS                       \
    { .chaos = 1,                               \
      .cport = 8880,                            \
      .dport = 8881,                            \
      .host = "127.0.0.1" }

struct arguments {
    const char *host;  /* Remote hostname to talk to */
    uint16_t cport;    /* Remote TCP port for command/control */
    uint16_t dport;    /* Remote UDP port listening for data packets */
    int chaos;         /* Chaos mode: randomly fail according to chaos.h */
};

static const char* program_name;

/*
 * Dummy registers
 */

typedef uint32_t reg_t;
/* Register map: indexes are RAW_RTYPE_*, values are pointers to that
 * module's registers */
typedef reg_t** reg_map_t;

/* Get a pointer to a module's registers.
 *
 * r_type: module's request type (RAW_RTYPE_*)
 *
 * The returned register map is indexed by the RAW_RADDR_* values for
 * that r_type. */
static inline reg_t* reg_map_get(reg_map_t reg_map, size_t r_type)
{
    return reg_map[r_type];
}

/* Allocate a register map. */
static reg_map_t reg_map_alloc(void)
{
    reg_t *err_reg_map = malloc(RAW_RADDR_ERR_NREGS * sizeof(reg_t));
    if (!err_reg_map) { goto noerr; }
    reg_t *top_reg_map = malloc(RAW_RADDR_TOP_NREGS * sizeof(reg_t));
    if (!top_reg_map) { goto notop; }
    reg_t *sata_reg_map = malloc(RAW_RADDR_SATA_NREGS * sizeof(reg_t));
    if (!sata_reg_map) { goto nosata; }
    reg_t *daq_reg_map = malloc(RAW_RADDR_DAQ_NREGS * sizeof(reg_t));
    if (!daq_reg_map) { goto nodaq; }
    reg_t *udp_reg_map = malloc(RAW_RADDR_UDP_NREGS * sizeof(reg_t));
    if (!udp_reg_map) { goto noudp; }
    reg_t *exp_reg_map = malloc(RAW_RADDR_EXP_NREGS * sizeof(reg_t));
    if (!exp_reg_map) { goto noexp; }

    reg_map_t ret = malloc(RAW_RTYPE_NTYPES * sizeof(reg_t*));
    if (!ret) { goto nomap; }
    ret[RAW_RTYPE_ERR] = err_reg_map;
    ret[RAW_RTYPE_TOP] = top_reg_map;
    ret[RAW_RTYPE_SATA] = sata_reg_map;
    ret[RAW_RTYPE_DAQ] = daq_reg_map;
    ret[RAW_RTYPE_UDP] = udp_reg_map;
    ret[RAW_RTYPE_EXP] = exp_reg_map;
    return ret;

 nomap:
    free(exp_reg_map);
 noexp:
    free(udp_reg_map);
 noudp:
    free(daq_reg_map);
 nodaq:
    free(sata_reg_map);
 nosata:
    free(top_reg_map);
 notop:
    free(err_reg_map);
 noerr:
    return 0;
}

/* Free a previously-allocated register map. */
static void reg_map_free(reg_map_t reg_map)
{
    free(reg_map_get(reg_map, RAW_RTYPE_ERR));
    free(reg_map_get(reg_map, RAW_RTYPE_TOP));
    free(reg_map_get(reg_map, RAW_RTYPE_SATA));
    free(reg_map_get(reg_map, RAW_RTYPE_DAQ));
    free(reg_map_get(reg_map, RAW_RTYPE_UDP));
    free(reg_map_get(reg_map, RAW_RTYPE_EXP));
    free(reg_map);
}

/*
 * struct daemon_session: encapsulates state needed for dealing with a
 * connected daemon
 */

struct daemon_session {
    int cc_sock;                /* listening command socket */
    int cc_comm_sock;           /* = accept(cc_sock, ....) */
    int dt_sock;                /* data socket */
    struct raw_pkt_cmd *req;
    struct raw_pkt_cmd *res;
    reg_map_t regs;
};

/* Convenience routines for struct daemon_session */

static inline struct raw_cmd_req* daemon_req(struct daemon_session *d_session)
{
    return raw_req(d_session->req);
}

static inline struct raw_cmd_req* daemon_res(struct daemon_session *d_session)
{
    return raw_req(d_session->res);
}

static void parse_args(struct arguments *args, int argc, char *const argv[])
{
    const char shortopts[] = "cC:D:H:";
    struct option longopts[] = {
        { .name = "chaos",
          .has_arg = optional_argument,
          .flag = 0,
          .val = 'c' },
        { .name = "cport",
          .has_arg = required_argument,
          .flag = 0,
          .val = 'C' },
        { .name = "dport",
          .has_arg = required_argument,
          .flag = 0,
          .val = 'D' },
        { .name = "remote-host",
          .has_arg = required_argument,
          .flag = 0,
          .val = 'H' },
        {0, 0, 0, 0},
    };
    while (1) {
        int option_idx = 0;
        int c = getopt_long(argc, argv, shortopts, longopts, &option_idx);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'c':
            args->chaos = strtol(optarg, (char**)0, 10);
            break;
        case 'C':
            args->cport = strtol(optarg, (char**)0, 10);
            break;
        case 'D':
            args->dport = strtol(optarg, (char**)0, 10);
            break;
        case 'h':
            args->host = optarg;
            break;
        case 0:                 /* fall through */
        case '?':               /* fall through */
        default:
            exit(EXIT_FAILURE);
        }
    }
}

/*
 * Request/response processing
 */

static int send_response(int sockfd, struct raw_pkt_cmd *res)
{
    assert(raw_mtype(res) == RAW_MTYPE_RES);
    int ret = raw_cmd_send(sockfd, res, MSG_NOSIGNAL);
    if (ret == -1) {
        log_WARNING("can't send response: %m");
    }
    return ret;
}

static int serve_unsupported(struct daemon_session *dsess)
{
    log_WARNING("unsupported request: "
                "r_id %u, r_type %u, r_addr %u, r_val %u.",
                raw_r_id(dsess->req), raw_r_type(dsess->req),
                raw_r_addr(dsess->req), raw_r_val(dsess->req));
    raw_packet_init(dsess->res, RAW_MTYPE_RES, RAW_PFLAG_ERR);
    struct raw_cmd_res *res_cmd = raw_res(dsess->res);
    struct raw_cmd_req *req_cmd = raw_req(dsess->req);
    res_cmd->r_id = req_cmd->r_id;
    res_cmd->r_addr = req_cmd->r_addr;
    res_cmd->r_val = 0;
    return send_response(dsess->cc_comm_sock, dsess->res);
}

static int serve_err(struct daemon_session *dsess)
{
    return serve_unsupported(dsess);
}

static int serve_top(struct daemon_session *dsess)
{
    return serve_unsupported(dsess);
}

static int serve_sata(struct daemon_session *dsess)
{
    return serve_unsupported(dsess);
}

static int serve_daq(struct daemon_session *dsess)
{
    return serve_unsupported(dsess);
}

static int serve_udp(struct daemon_session *dsess)
{
    return serve_unsupported(dsess);
}

static int serve_exp(struct daemon_session *dsess)
{
    return serve_unsupported(dsess);
}

typedef int (*serve_fn)(struct daemon_session*);

/* Close dsess->cc_comm_sock if it's not -1, and then set it to -1. */
static int close_comm_sock(struct daemon_session *dsess)
{
    if (dsess->cc_comm_sock != -1 && close(dsess->cc_comm_sock) == -1) {
        log_ERR("close(dsess->cc_comm_sock): %m");
        return -1;
    }
    dsess->cc_comm_sock = -1;
    return 0;
}

/* Call close_comm_sock(dsess), then accept() a new one. */
static int reopen_comm_sock(struct daemon_session *dsess)
{
    if (close_comm_sock(dsess) == -1) {
        return -1;
    }
    dsess->cc_comm_sock = accept(dsess->cc_sock, NULL, NULL);
    return 0;
}

/* Create a command/control socket and serve requests from it for as
 * long as possible. Returns an exit status if an unrecoverable error
 * occurs. */
static int serve_requests(struct daemon_session *dsess)
{
    log_INFO("waiting for daemon");
    if (reopen_comm_sock(dsess) == -1) {
        log_ERR("can't accept() daemon connection: %m");
        goto bail;
    }
    log_INFO("serving requests");
    while (1) {
        /* Get the request. */
        raw_packet_init(dsess->req, RAW_MTYPE_REQ, 0);
        int rstatus = raw_cmd_recv(dsess->cc_comm_sock, dsess->req,
                                   MSG_NOSIGNAL);
        if (rstatus == 0 || (rstatus == -1 && errno == EPIPE)) {
            /* TODO use this as a reset or sync-type signal, and be smarter. */
            log_INFO("lost daemon connection; waiting for re-connect");
            if (reopen_comm_sock(dsess) == -1) {
                log_ERR("can't accept() daemon connection: %m");
                goto bail;
            }
            continue;
        }
        if (rstatus == -1) {
            log_INFO("raw_cmd_recv(): %m; bailing");
            goto bail;
        }
        /* TODO protocol version checking */
        /* Well-behaved daemons don't send us error packets. */
        assert(!raw_pkt_is_err(dsess->req));
        /* Respond to the request. */
        serve_fn serve = 0;
        switch (raw_r_type(dsess->req)) {
        case RAW_RTYPE_ERR:
            serve = serve_err;
            break;
        case RAW_RTYPE_TOP:
            serve = serve_top;
            break;
        case RAW_RTYPE_SATA:
            serve = serve_sata;
            break;
        case RAW_RTYPE_DAQ:
            serve = serve_daq;
            break;
        case RAW_RTYPE_UDP:
            serve = serve_udp;
            break;
        case RAW_RTYPE_EXP:
            serve = serve_exp;
            break;
        default:
            log_WARNING("ignoring unexpected r_type %u",
                        raw_r_type(dsess->req));
            continue;
        }
        int serve_status = serve(dsess);
        if (serve_status == -1) {
            log_ERR("bailing"); /* TODO be smarter */
            goto bail;
        }
    }

 bail:
    if (dsess->cc_comm_sock != -1 && close(dsess->cc_comm_sock) == -1) {
        log_ERR("can't close socket connected to remote: %m");
    }
    return EXIT_FAILURE;
}

/* For debugging, use an obvious default register value; real value is
 * "undefined" */
#define REG_DEFAULT 0xdeadbeef
static void init_default_reg_vals(reg_map_t reg_map)
{
    for (size_t rtype = 0; rtype < RAW_RTYPE_NTYPES; rtype++) {
        ssize_t nregs;
        switch (rtype) {
        case RAW_RTYPE_ERR:
            nregs = RAW_RADDR_ERR_NREGS;
            break;
        case RAW_RTYPE_TOP:
            nregs = RAW_RADDR_TOP_NREGS;
            break;
        case RAW_RTYPE_SATA:
            nregs = RAW_RADDR_SATA_NREGS;
            break;
        case RAW_RTYPE_DAQ:
            nregs = RAW_RADDR_DAQ_NREGS;
            break;
        case RAW_RTYPE_UDP:
            nregs = RAW_RADDR_UDP_NREGS;
            break;
        case RAW_RTYPE_EXP:
            nregs = RAW_RADDR_EXP_NREGS;
            break;
        default:
            log_WARNING("unknown request type %zu added; you should add "
                        "dummy-datanode support for it", rtype);
            nregs = -1;
            break;
        }
        if (nregs < 0) {
            continue;
        }
        reg_t *mod_regs = reg_map_get(reg_map, rtype);
        for (size_t reg = 0; reg < (size_t)nregs; reg++) {
            mod_regs[reg] = REG_DEFAULT;
        }
    }
}

static int dummy_datanode_start(struct arguments *args)
{
    int ret = EXIT_FAILURE;

    /*
     * Initialize daemon session
     */

    /* Sockets */
    int cc_sock = sockutil_get_tcp_passive(args->cport);
    if (cc_sock == -1) {
        log_ERR("can't make cc_sockfd: %m");
        goto nocc;
    }
    int dt_sock = sockutil_get_udp_connected_p(args->host, args->dport);
    if (dt_sock == -1) {
        log_ERR("can't make dt_sockfd: %m");
        goto nodt;
    }
    /* Registers */
    reg_map_t reg_map = reg_map_alloc();
    if (!reg_map) {
        goto noregs;
    }
    init_default_reg_vals(reg_map);
    /* Packets */
    struct raw_pkt_cmd req_pkt;
    raw_packet_init(&req_pkt, RAW_MTYPE_REQ, 0);
    struct raw_pkt_cmd res_pkt;
    raw_packet_init(&res_pkt, RAW_MTYPE_RES, 0);

    struct daemon_session dsess = {
        .cc_sock = cc_sock,
        .cc_comm_sock = -1,     /* will be dealt with later */
        .dt_sock = dt_sock,
        .req = &req_pkt,
        .res = &res_pkt,
        .regs = reg_map,
    };

    /*
     * Serve requests forever, or until a Terrible Event.
     */
    ret = serve_requests(&dsess);

    /*
     * Bail.
     */
    reg_map_free(reg_map);
 noregs:
    if (close(dt_sock) == -1) {
        log_ERR("close(dt_sock): %m");
        ret = EXIT_FAILURE;
    }
 nodt:
    if (close(cc_sock) == -1) {
        log_ERR("close(cc_sock): %m");
        ret = EXIT_FAILURE;
    }
 nocc:
    return ret;
}

int main(int argc, char *argv[])
{
    /* Setup */
    int log_to_stderr = 1;
    struct arguments args = DEFAULT_ARGUMENTS;
    char *pnamep = strrchr(argv[0], '/');
    if (pnamep != NULL) {
        pnamep++;
    } else {
        pnamep = argv[0];
    }
    program_name = strdup(pnamep);
    if (!program_name) {
        fprintf(stderr, "out of memory\n");
        exit(EXIT_FAILURE);
    }
    logging_init(program_name, LOG_DEBUG, log_to_stderr);
    parse_args(&args, argc, argv);
    log_INFO("remote host: %s, C/C port %u, data port %u, chaos: %s",
             args.host, args.cport, args.dport,
             args.chaos ? "enabled" : "disabled");
    chaos_init(args.chaos);
    int ret = dummy_datanode_start(&args);
    logging_fini();
    exit(ret);
}
