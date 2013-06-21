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

static int sockutil_get_socket_h(int socktype, int passive,
                                 const char *host, uint16_t port,
                                 sock_cfg_fn sock_cfg,
                                 struct addrinfo *hints)
{
    int ret = -1;

    struct addrinfo defaults;
    if (!hints) {
        memset(&defaults, 0, sizeof(struct addrinfo));
        defaults.ai_canonname = NULL;
        defaults.ai_addr = NULL;
        defaults.ai_next = NULL;
        defaults.ai_flags = (passive ? AI_PASSIVE : 0) | AI_NUMERICSERV;
        defaults.ai_family = AF_UNSPEC;
        defaults.ai_socktype = socktype;
        hints = &defaults;
    }

    char port_str[20];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo *ai_results;
    int gai_ret = getaddrinfo(host, port_str, hints, &ai_results);
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

static inline int sockutil_get_socket(int socktype, int passive,
                                      const char *host, uint16_t port,
                                      sock_cfg_fn sock_cfg)
{
    return sockutil_get_socket_h(socktype, passive, host, port, sock_cfg,
                                 NULL);
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

int sockutil_get_tcp_passive(uint16_t port, int backlog)
{
    int sock = sockutil_get_socket(SOCK_STREAM, 1, NULL, port,
                                   sockutil_cfg_bind_sock);
    if (sock == -1) {
        return -1;
    }
    if (listen(sock, backlog) == -1) {
        close(sock);
        return -1;
    }
    return sock;
}

int sockutil_get_tcp_connected_p(const char *host, uint16_t port)
{
    return sockutil_get_socket(SOCK_STREAM, 0, host, port,
                               sockutil_cfg_conn);
}
