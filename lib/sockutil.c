/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "logging.h"

/* Socket configuration function, for sockutil_get_socket(). Takes a
 * socket and the struct addrinfo used to create it as arguments;
 * returns 0 if socket is successfully configured, or -1 on error. */
typedef int (*sock_cfg_fn)(int, struct addrinfo*);

static int sockutil_get_socket(int socktype, int passive,
                               const char *host, uint16_t port,
                               sock_cfg_fn sock_cfg)
{
    int ret = -1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    hints.ai_flags = (passive ? AI_PASSIVE : 0) | AI_NUMERICSERV;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;

    char port_str[20];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo *ai_results;
    int gai_ret = getaddrinfo(host, port_str, &hints, &ai_results);
    if (gai_ret != 0) {
        // If getaddrinfo() fails, we might try falling back on
        // calling socket(AF_INET, socktype, 0) ourselves to try to
        // get an IPv4 socket. But until that's actually a problem,
        // just scream and die.
        if (gai_ret == EAI_SYSTEM) {
            log_ERR("getaddrinfo: %m");
        } else {
            log_ERR("getaddrinfo: %s", gai_strerror(gai_ret));
        }
        return -1;
    }

    for (struct addrinfo *arp = ai_results; arp != NULL; arp = arp->ai_next) {
        int sckt = socket(arp->ai_family, arp->ai_socktype,
                          arp->ai_protocol);
        if (sckt == -1) {
            continue;
        }
        if (sock_cfg(sckt, arp) == -1) {
            close(sckt);
            continue;
        }

        // Success!
        ret = sckt;
        break;
    }

    freeaddrinfo(ai_results);

    return ret;
}

static int sockutil_cfg_bind_sock(int sock, struct addrinfo *arp)
{
    int reuse_addr = 1;
    if (-1 == setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                         &reuse_addr, sizeof(int))) {
        return -1;
    }
    return bind(sock, arp->ai_addr, arp->ai_addrlen);
}

static int sockutil_cfg_conn(int sock, struct addrinfo *arp)
{
    return connect(sock, arp->ai_addr, arp->ai_addrlen);
}

int sockutil_get_udp_socket(uint16_t port)
{
    return sockutil_get_socket(SOCK_DGRAM, 1, NULL, port,
                               sockutil_cfg_bind_sock);
}

int sockutil_get_udp_connected_p(const char *host, uint16_t port)
{
    return sockutil_get_socket(SOCK_DGRAM, 0, host, port, sockutil_cfg_conn);
}

static int sockutil_cfg_tcp_passive(int sock, struct addrinfo *arp)
{
    if (sockutil_cfg_bind_sock(sock, arp) == -1) {
        return -1;
    }
    if (listen(sock, 5) == -1) {
        return -1;
    }
    return 0;
}

int sockutil_get_tcp_passive(uint16_t port)
{
    return sockutil_get_socket(SOCK_STREAM, 1, NULL, port,
                               sockutil_cfg_tcp_passive);
}

int sockutil_get_tcp_connected_p(const char *host, uint16_t port)
{
    return sockutil_get_socket(SOCK_STREAM, 0, host, port,
                               sockutil_cfg_conn);
}
