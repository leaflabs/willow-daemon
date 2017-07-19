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

#include "sockutil.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "logging.h"

int sockutil_ntop(struct sockaddr *a, char *dst, socklen_t size)
{
    const char *in_s = NULL;
    switch (a->sa_family) {
    case AF_INET: {
        struct sockaddr_in *ain = (struct sockaddr_in*)a;
        if (size < INET_ADDRSTRLEN) {
            return -1;
        }
        in_s = inet_ntop(AF_INET, &ain->sin_addr, dst, size);
        break;
    }
    case AF_INET6: {
        struct sockaddr_in6 *ain6 = (struct sockaddr_in6*)a;
        if (size < INET6_ADDRSTRLEN) {
            return -1;
        }
        in_s = inet_ntop(AF_INET6, &ain6->sin6_addr, dst, size);
        break;
    }
    default:
        return -1;
    }
    return in_s == NULL ? -1 : 0;
}

static int sockutil_a4_eq(struct sockaddr_in *a, struct sockaddr_in *b,
                          unsigned ignore)
{
    if (!(ignore & SOCKUTIL_IGN_PORT) && (a->sin_port != b->sin_port)) {
        return 0;
    }
    if (!(ignore & SOCKUTIL_IGN_ADDR) && (a->sin_addr.s_addr !=
                                          b->sin_addr.s_addr)) {
        return 0;
    }
    return 1;
}

static int sockutil_a6_eq(struct sockaddr_in6 *a, struct sockaddr_in6 *b,
                          unsigned ignore)
{
    if (!(ignore & SOCKUTIL_IGN_PORT) && (a->sin6_port != b->sin6_port)) {
        return 0;
    }
    if (!(ignore & SOCKUTIL_IGN_ADDR) && memcmp(&a->sin6_addr,
                                                &b->sin6_addr,
                                                sizeof(struct in6_addr))) {
        return 0;
    }
    if (!(ignore & SOCKUTIL_IGN_FLOW) && (a->sin6_flowinfo !=
                                          b->sin6_flowinfo)) {
        return 0;
    }
    if (!(ignore & SOCKUTIL_IGN_SCOPE) && (a->sin6_scope_id !=
                                           b->sin6_scope_id)) {
        return 0;
    }
    return 1;
}

int sockutil_addr_eq(struct sockaddr *a, struct sockaddr *b, unsigned ignore)
{
    assert(a->sa_family == AF_INET || a->sa_family == AF_INET6);
    assert(b->sa_family == AF_INET || b->sa_family == AF_INET6);
    if (a->sa_family != b->sa_family) {
        return 0;
    }
    return (a->sa_family == AF_INET) ?
        sockutil_a4_eq((struct sockaddr_in*)a, (struct sockaddr_in*)b,
                       ignore) :
        sockutil_a6_eq((struct sockaddr_in6*)a, (struct sockaddr_in6*)b,
                       ignore);
}

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

int sockutil_get_udp_connected(struct sockaddr *addr, socklen_t addrlen)
{
    int ret = socket(addr->sa_family, SOCK_DGRAM, 0);
    if (ret == -1) {
        goto bail;
    }
    if (connect(ret, addr, addrlen)) {
        goto bail;
    }
    return ret;
 bail:
    if (ret != -1) {
        close(ret);             /* swallow any errors */
    }
    return -1;
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

static int sin_addr_eq(struct sockaddr_in *a, struct sockaddr_in *b)
{
    return a->sin_addr.s_addr == b->sin_addr.s_addr;
}

static int sin6_addr_eq(struct sockaddr_in6 *a, struct sockaddr_in6 *b)
{
    return 0 == memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(struct in6_addr));
}

int sockutil_get_sock_iface(int sockfd, int *iface)
{
    int ret = -1;
    struct sockaddr_storage sas;
    socklen_t sas_len = sizeof(sas);
    if (getsockname(sockfd, (struct sockaddr*)&sas, &sas_len)) {
        return -1;
    }
    assert(sas_len <= sizeof(sas)); /* by definition of sockaddr_storage */
    struct ifaddrs *ifaddrs;
    if (getifaddrs(&ifaddrs)) {
        return -1;
    }
    for (struct ifaddrs *ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name) {
            continue;
        }
        int family = ifa->ifa_addr->sa_family;
        unsigned ifidx = if_nametoindex(ifa->ifa_name);
        if (ifidx == 0) {
            log_ERR("can't convert iface name %s to index: %m", ifa->ifa_name);
            break;
        }
        if (family == AF_INET && sas.ss_family == AF_INET) {
            if (sin_addr_eq((struct sockaddr_in*)ifa->ifa_addr,
                            (struct sockaddr_in*)&sas)) {
                *iface = ifidx;
                break;
            }
        } else if (family == AF_INET6 && sas.ss_family == AF_INET6) {
            if (sin6_addr_eq((struct sockaddr_in6*)ifa->ifa_addr,
                             (struct sockaddr_in6*)&sas)) {
                *iface = ifidx;
                break;
            }
        }
    }
    freeifaddrs(ifaddrs);
    return ret;
}

int sockutil_get_iface_addr(unsigned iface, int family,
                            struct sockaddr *addr, socklen_t *len)
{
    int ret = -1;
    struct ifaddrs *ifaddrs;
    if (getifaddrs(&ifaddrs)) {
        return -1;
    }
    for (struct ifaddrs *ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name) {
            continue;
        }
        int ifa_family = ifa->ifa_addr->sa_family;
        unsigned ifidx = if_nametoindex(ifa->ifa_name);
        if (ifidx == 0) {
            log_ERR("can't convert iface %s to index: %m", ifa->ifa_name);
            break;
        }
        if (iface == ifidx && family == ifa_family) {
            socklen_t tocopy;
            if (family == AF_INET) {
                tocopy = sizeof(struct sockaddr_in);
            } else if (family == AF_INET6) {
                tocopy = sizeof(struct sockaddr_in6);
            } else {
                log_WARNING("%s: unsupported address family %d", __func__,
                            family);
                break;
            }
            memcpy(addr, ifa->ifa_addr, tocopy > *len ? *len : tocopy);
            *len = tocopy;
            ret = 0;
            break;
        }
    }
    freeifaddrs(ifaddrs);
    return ret;
}

/* MASSIVE HACK ALERT (but thanks, sysfs!) */
#define SYSFS_PREFIX "/sys/class/net/"
#define SYSFS_POSTFIX "/address"
int sockutil_get_iface_hwaddr(unsigned iface, uint8_t *hwaddr, size_t *len)
{
    /* sysfs tells us HW addresses for each <iface> in
     * "aa:bb:cc:ee:ff" ASCII format in the files
     * "/sys/class/net/<iface>/address".
     *
     * 18 == strlen("aa:bb:cc:ee:ff") + 1 */
    char hack[18];

    int ret = -1;
    char *buf = NULL;
    int fd = -1;
    char ifname[IFNAMSIZ];

    if (if_indextoname(iface, ifname) == NULL) {
        return -1;
    }
    size_t iface_len = strlen(ifname);

    if (*len < 6) {
        /* um, you did want a MAC48, right? */
        goto bail;
    }

    size_t buflen = strlen(SYSFS_PREFIX SYSFS_POSTFIX) + iface_len + 1;
    buf = malloc(buflen);
    if (!buf) {
        goto bail;
    }
    int s = snprintf(buf, buflen, SYSFS_PREFIX "%s" SYSFS_POSTFIX, ifname);
    if (s < 0) {
        goto bail;
    }
    assert((size_t)s < buflen); /* or output was truncated -> can't happen */
    fd = open(buf, O_RDONLY);
    if (fd == -1) {
        /* no sysfs :( */
        log_WARNING("can't open %s; do you have sysfs?", buf);
        goto bail;
    }

    size_t nread = 0;
    size_t toread = sizeof(hack) - 1;
    while (nread < toread) {
        ssize_t n = read(fd, hack + nread, toread - nread);
        if (n == 0 || (n < 0 && errno != EINTR)) {
            goto bail;
        }
        nread += (size_t)n;
    }
    hack[toread] = '\0';
    /* Make sure this looks like what we expect */
    if (!(hack[2] == ':' && hack[5] == ':' && hack[8] == ':' &&
          hack[11] == ':')) {
        log_WARNING("unexpected results while reading %s: %s", buf, hack);
        goto bail;
    }
    /* Convert ASCII MAC48 to bytes */
    for (size_t i = 0; i < 6; i++) {
        hwaddr[i] = (uint8_t)strtol(hack + i * 3, NULL, 16);
    }
    *len = 6;
    ret = 0;

 bail:
    if (buf) {
        free(buf);
    }
    if (fd != -1 && close(fd)) {
        ret = -1;
    }
    return ret;
}

int sockutil_set_tcp_nodelay(int sockfd)
{
    int one = 1;

    return setsockopt(sockfd,
                      IPPROTO_TCP,
                      TCP_NODELAY, /* send immediately */
                      &one,
                      sizeof(one));
}
