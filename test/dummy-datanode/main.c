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
      .dport = 6660,                            \
      .host = "127.0.0.1" }

#define REG_DEFAULT 0xdeadbeef  /* poison value for dummy register init */

struct arguments {
    const char *host;  /* Remote hostname to talk to */
    uint16_t cport;    /* Daemon control socket TCP port to connect to */
    uint16_t dport;    /* Local UDP port to send data packets from */
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
    reg_t *central_reg_map = malloc(RAW_RADDR_CENTRAL_NREGS * sizeof(reg_t));
    if (!central_reg_map) { goto nocentral; }
    reg_t *sata_reg_map = malloc(RAW_RADDR_SATA_NREGS * sizeof(reg_t));
    if (!sata_reg_map) { goto nosata; }
    reg_t *daq_reg_map = malloc(RAW_RADDR_DAQ_NREGS * sizeof(reg_t));
    if (!daq_reg_map) { goto nodaq; }
    reg_t *udp_reg_map = malloc(RAW_RADDR_UDP_NREGS * sizeof(reg_t));
    if (!udp_reg_map) { goto noudp; }
    reg_t *gpio_reg_map = malloc(RAW_RADDR_GPIO_NREGS * sizeof(reg_t));
    if (!gpio_reg_map) { goto nogpio; }

    reg_map_t ret = malloc(RAW_RTYPE_NTYPES * sizeof(reg_t*));
    if (!ret) { goto nomap; }
    ret[RAW_RTYPE_ERR] = err_reg_map;
    ret[RAW_RTYPE_CENTRAL] = central_reg_map;
    ret[RAW_RTYPE_SATA] = sata_reg_map;
    ret[RAW_RTYPE_DAQ] = daq_reg_map;
    ret[RAW_RTYPE_UDP] = udp_reg_map;
    ret[RAW_RTYPE_GPIO] = gpio_reg_map;
    return ret;

 nomap:
    free(gpio_reg_map);
 nogpio:
    free(udp_reg_map);
 noudp:
    free(daq_reg_map);
 nodaq:
    free(sata_reg_map);
 nosata:
    free(central_reg_map);
 nocentral:
    free(err_reg_map);
 noerr:
    return 0;
}

/* Free a previously-allocated register map. */
static void reg_map_free(reg_map_t reg_map)
{
    free(reg_map_get(reg_map, RAW_RTYPE_ERR));
    free(reg_map_get(reg_map, RAW_RTYPE_CENTRAL));
    free(reg_map_get(reg_map, RAW_RTYPE_SATA));
    free(reg_map_get(reg_map, RAW_RTYPE_DAQ));
    free(reg_map_get(reg_map, RAW_RTYPE_UDP));
    free(reg_map_get(reg_map, RAW_RTYPE_GPIO));
    free(reg_map);
}

/*
 * struct daemon_session: encapsulates state needed for dealing with a
 * connected daemon
 */

struct daemon_session {
    int cc_sock;                /* connected command socket */
    const char *cc_addr;        /* daemon address, presentation format */
    uint16_t cc_port;           /* daemon control port */
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
 *
 * TODO add read permissions checks as necessary
 */

#define STRLEN_RAW_RADDR_ 10    /* strlen("RAW_ADDR_") */
#define DEBUG_LOG_RCMD_IOD(mtype, ph)                           \
    (mtype == RAW_MTYPE_REQ ?                                   \
        (((ph)->p_flags & RAW_PFLAG_RIOD) == RAW_PFLAG_RIOD_R ? \
         "(r)" : "(w)") :                                       \
     "   ")
#define DEBUG_LOG_RCMD(mtype, rcmd, ph)                                 \
    log_DEBUG("%s %u: pflags 0x%x %s, reg=%s, val=%u (0x%x)",           \
              mtype == RAW_MTYPE_REQ ? "req" : "res",                   \
              (rcmd)->r_id,                                             \
              (ph)->p_flags,                                            \
              DEBUG_LOG_RCMD_IOD(mtype, ph),                            \
              raw_r_addr_str((rcmd)->r_type,                            \
                             (rcmd)->r_addr) + STRLEN_RAW_RADDR_,       \
              (rcmd)->r_val,                                            \
              (rcmd)->r_val)

static int send_response(int sockfd, struct raw_pkt_cmd *res)
{
    assert(raw_mtype(res) == RAW_MTYPE_RES);
    DEBUG_LOG_RCMD(RAW_MTYPE_RES, raw_res(res), &res->ph);
    int ret = raw_cmd_send(sockfd, res, MSG_NOSIGNAL);
    if (ret == -1) {
        log_WARNING("can't send response: %m");
    }
    return ret;
}

static int serve_request_error(struct daemon_session *dsess)
{
    struct raw_pkt_cmd *req = dsess->req;
    struct raw_pkt_cmd *res = dsess->res;
    log_WARNING("unsupported or erroneous request: "
                "r_id %u, r_type %u, r_addr %u, r_val %u.",
                raw_r_id(req), raw_r_type(req),
                raw_r_addr(req), raw_r_val(req));
    raw_packet_init(res, RAW_MTYPE_RES, RAW_PFLAG_ERR);
    struct raw_cmd_res *res_cmd = raw_res(res);
    struct raw_cmd_req *req_cmd = raw_req(req);
    res_cmd->r_id = req_cmd->r_id;
    res_cmd->r_addr = req_cmd->r_addr;
    res_cmd->r_val = REG_DEFAULT;
    return send_response(dsess->cc_sock, dsess->res);
}

static int serve_reg_read(struct daemon_session *dsess)
{
    struct raw_cmd_req *req_cmd = raw_req(dsess->req);
    struct raw_cmd_res *res_cmd = raw_res(dsess->res);
    reg_t *regs = reg_map_get(dsess->regs, req_cmd->r_type);
    uint32_t reg_val = regs[req_cmd->r_addr];
    res_cmd->r_id = req_cmd->r_id;
    res_cmd->r_type = req_cmd->r_type;
    res_cmd->r_addr = req_cmd->r_addr;
    res_cmd->r_val = reg_val;
    return send_response(dsess->cc_sock, dsess->res);
}

static int serve_reg_write(struct daemon_session *dsess)
{
    struct raw_cmd_req *req_cmd = raw_req(dsess->req);
    struct raw_cmd_res *res_cmd = raw_res(dsess->res);
    reg_t *regs = reg_map_get(dsess->regs, req_cmd->r_type);
    uint32_t new_val = req_cmd->r_val;
    regs[req_cmd->r_addr] = new_val;
    res_cmd->r_id = req_cmd->r_id;
    res_cmd->r_type = req_cmd->r_type;
    res_cmd->r_addr = req_cmd->r_addr;
    res_cmd->r_val = new_val;
    return send_response(dsess->cc_sock, dsess->res);
}

static int serve_central_write(struct daemon_session *dsess) /* TODO */
{
    return serve_reg_write(dsess);
}

static int serve_sata_write(struct daemon_session *dsess) /* TODO */
{
    return serve_reg_write(dsess);
}

static int serve_daq_write(struct daemon_session *dsess) /* TODO */
{
    return serve_reg_write(dsess);
}

static int serve_udp_write(struct daemon_session *dsess) /* TODO */
{
    return serve_reg_write(dsess);
}

static int serve_gpio_write(struct daemon_session *dsess) /* TODO */
{
    return serve_reg_write(dsess);
}

typedef int (*serve_fn)(struct daemon_session*);

static int serve_request(struct daemon_session *dsess)
{
    struct raw_cmd_req *rcmd = raw_req(dsess->req);

    DEBUG_LOG_RCMD(RAW_MTYPE_REQ, rcmd, &dsess->req->ph);

    static const serve_fn write_servers[] = {
        /* The daemon sending _us_ an error is illegal. */
        [RAW_RTYPE_ERR] = serve_request_error,

        [RAW_RTYPE_CENTRAL] = serve_central_write,
        [RAW_RTYPE_SATA]    = serve_sata_write,
        [RAW_RTYPE_DAQ]     = serve_daq_write,
        [RAW_RTYPE_UDP]     = serve_udp_write,
        [RAW_RTYPE_GPIO]    = serve_gpio_write,
    };
    int module_n_regs = raw_num_regs(rcmd->r_type);
    serve_fn serve = NULL;
    if (rcmd->r_type >= RAW_RTYPE_NTYPES) {
        log_WARNING("request with unknown r_type %u", rcmd->r_type);
        serve = serve_request_error;
    } else if (rcmd->r_addr >= module_n_regs) {
        log_WARNING("request r_type %u has r_addr %u, but max is %u",
                    rcmd->r_type, rcmd->r_addr, module_n_regs);
        serve = serve_request_error;
    } else if (raw_pflags(dsess->req) & RAW_PFLAG_RIOD_R) {
        /* Register read; nothing special required at the moment. */
        if (rcmd->r_val != 0) {
            serve = serve_request_error; /* Reads must set r_val=0 */
        } else {
            serve = serve_reg_read;
        }
    } else {
        /* Register write. */
        serve = write_servers[rcmd->r_type];
    }
    if (!serve) {
        log_ERR("WTF? no serve function found");
        return -1;
    }
    return serve(dsess);
}

/* Call close_comm_sock(dsess), then accept() a new one. */
static int reopen_control_sock(struct daemon_session *dsess)
{
    if (dsess->cc_sock != -1) {
        if (close(dsess->cc_sock) == -1) {
            return -1;
        }
    }
    dsess->cc_sock = sockutil_get_tcp_connected_p(dsess->cc_addr,
                                                  dsess->cc_port);
    return dsess->cc_sock;
}

/* Create a command/control socket and serve requests from it for as
 * long as possible. Returns an exit status if an unrecoverable error
 * occurs. */
static int serve_requests(struct daemon_session *dsess)
{
    log_INFO("serving requests");
    while (1) {
        /*
         * Get the request.
         */
        int rstatus = 0;
        if (dsess->cc_sock != -1) {
            raw_packet_init(dsess->req, RAW_MTYPE_REQ, 0);
            rstatus = raw_cmd_recv(dsess->cc_sock, dsess->req, MSG_NOSIGNAL);
        }

        /*
         * Status checks.
         */
        if (rstatus == 0 || (rstatus == -1 && errno == EPIPE)) {
            /* TODO use this as a reset or sync-type signal, and be smarter. */
            log_INFO("connecting to daemon");
            int first = 1;
            while (reopen_control_sock(dsess) == -1) {
                if (first) {
                    log_INFO("can't connect to daemon: %m; "
                             "will retry periodically");
                    first = 0;
                }
                sleep(3);
            }
            log_INFO("connected to daemon");
            continue;
        }
        if (rstatus == -1) {
            log_INFO("raw_cmd_recv(): %m; bailing");
            goto bail;
        }
        /* TODO protocol version checking */
        /* Well-behaved daemons don't send us error packets. */
        assert(!raw_pkt_is_err(dsess->req));

        /*
         * Respond to the request.
         */
        if (serve_request(dsess) == -1) {
            log_INFO("can't serve request; bailing"); /* TODO be smarter */
            goto bail;
        }
    }

 bail:
    if (dsess->cc_sock != -1 && close(dsess->cc_sock) == -1) {
        log_ERR("can't close() daemon connection: %m");
    }
    return EXIT_FAILURE;
}

/* For debugging, use an obvious default register value; real value is
 * "undefined". Note that some default register values are special-cased. */
static void init_default_reg_vals(reg_map_t reg_map)
{
    for (size_t rtype = 0; rtype < RAW_RTYPE_NTYPES; rtype++) {
        int nregs = raw_num_regs((uint8_t)rtype);
        if (nregs < 0) {
            log_ERR("WTF? raw_num_regs(%zu) = %d", rtype, nregs);
            continue;
        }
        reg_t *mod_regs = reg_map_get(reg_map, rtype);
        for (size_t reg = 0; reg < (size_t)nregs; reg++) {
            if (rtype == RAW_RTYPE_DAQ && reg == RAW_RADDR_DAQ_CHIP_ALIVE) {
                /* TODO add some chaos support here for chips going down */
                mod_regs[reg] = 0xFFFFFFFF;
            } else {
                mod_regs[reg] = REG_DEFAULT;
            }
        }
    }
}

static int dummy_datanode_start(struct arguments *args)
{
    int ret = EXIT_FAILURE;

    /*
     * Initialize daemon session
     */

#define DAEMON_ADDR "127.0.0.1"
    /* Sockets */
    int cc_sock = sockutil_get_tcp_connected_p(DAEMON_ADDR, args->cport);
    if (cc_sock == -1) {
        log_WARNING("can't make cc_sockfd: %m");
    }
    int dt_sock = sockutil_get_udp_socket(args->dport);
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
        .cc_addr = DAEMON_ADDR,
        .cc_port = args->cport,
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
