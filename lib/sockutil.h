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

/**
 * @file sockutil.h
 * @brief Socket utility library
 */

#ifndef _LIB_SOCKUTIL_H_
#define _LIB_SOCKUTIL_H_

#include <assert.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

static inline socklen_t sockutil_addrlen(struct sockaddr *a)
{
    switch (a->sa_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    default:
        assert(0);
        return 0;
    }
}

static inline ssize_t sockutil_addrstrlen(struct sockaddr *a)
{
    switch (a->sa_family) {
    case AF_INET: return INET_ADDRSTRLEN;
    case AF_INET6: return INET6_ADDRSTRLEN;
    default: return -1;
    }
}

#define SOCKUTIL_IGN_PORT 0x2   /* Port */
#define SOCKUTIL_IGN_ADDR 0x4   /* Address */
#define SOCKUTIL_IGN_FLOW 0x8   /* IPv6 flow information */
#define SOCKUTIL_IGN_SCOPE 0x10 /* IPv6 scope ID */
/**
 * @brief Test if two socket addresses are equal.
 *
 * The socket addresses must have families that are either AF_INET or
 * AF_INET6.
 *
 * @param a First socket address
 * @param b Second socket address
 * @param ignore SOCKUTIL_IGN_* fields to ignore when testing for equality
 *
 * @return Zero if unequal, nonzero otherwise
 */
int sockutil_addr_eq(struct sockaddr *a, struct sockaddr *b, unsigned ignore);

/**
 * @brief Convenience for creating UDP sockets.
 *
 * Try to socket() and bind() a new UDP socket at the specified port,
 * using IPv4 or IPv6 as available.
 *
 * @param port Port to open a socket on.
 * @return On success, the socket file descriptor. On failure, an
 *         invalid socket (-1).
 */
int sockutil_get_udp_socket(uint16_t port);

/**
 * @brief Convenience for creating connected UDP sockets.
 *
 * @param host Host to connect to, presentation format (IPv4 dotted
 *             quad or IPv6 hex string).
 * @param port Port to connect to.
 * @return Socket file descriptor on success, -1 on failure.
 */
int sockutil_get_udp_connected_p(const char *host, uint16_t port);

/**
 * @brief Convenience for creating connected UDP socket, given sockaddr.
 * @param addr Address to connect to
 * @param addrlen Length of "addr" structure
 * @return Socket file descriptor on success, -1 on failure.
 */
int sockutil_get_udp_connected(struct sockaddr *addr, socklen_t addrlen);

/**
 * @brief Convenience for creating passive TCP sockets.
 *
 * @param port Port to create the socket on.
 * @param backlog Number of pending connections to allow; passed to listen().
 * @return Socket file descriptor on success, -1 on failure.
 */
int sockutil_get_tcp_passive(uint16_t port, int backlog);

/**
 * @brief Convenience for creating connected TCP sockets.
 *
 * @param host Host to connect to, presentation format (IPv4 dotted
 *             quad or IPv6 hex string).
 * @param port Port to connect to on host.
 * @return Socket file descriptor on success, -1 on failure.
 */
int sockutil_get_tcp_connected_p(const char *host, uint16_t port);

/**
 * @brief Get the name of the network interface associated with a socket
 * @param sockfd Socket whose network interface's name to get
 * @param iface Return value: interface number (see <net/if.h>)
 * @return 0 on success, -1 on failure.
 */
int sockutil_get_sock_iface(int sockfd, int *iface);

/**
 * @brief Get an interface address associated for an address family.
 *
 * @param iface Interface number whose address to get
 * @param family Family (AF_INET, AF_INET6)
 * @param addr Returned address
 * @param len Maximum number of bytes in addr to write; on return,
 *            number written. This exceeds initial value on
 *            truncation.
 * @return 0 on success, -1 on failure.
 */
int sockutil_get_iface_addr(unsigned iface, int family,
                            struct sockaddr *addr, socklen_t *len);

/**
 * @brief Get hardware (MAC48 only for now) address for a network interface
 *
 * @param iface Interface's number; see <net/if.h>
 * @param hwaddr Buffer to write address into.
 * @param len Points to maximum number of bytes to store in hwaddr
 *            (currently, must be at least 6). On return, contains
 *            actual number of bytes stored (will be larger than on
 *            entry if truncation occurred).
 * @return 0 on success, -1 on failure.
 */
int sockutil_get_iface_hwaddr(unsigned iface, uint8_t *hwaddr, size_t *len);

/**
 * @brief Convenience for a pair of calls to sockutil_get_sock_iface()
 *        and sockutil_get_iface_hwaddr()
 *
 * @param sockfd Socket whose hardware address to get
 * @param hwaddr Buffer to store hardware address in
 * @param len Maximum number of bytes in buffer
 * @return 0 on success, -1 on failure
 * @see sockutil_get_sock_iface(), sockutil_get_iface_hwaddr()
 */
static inline int sockutil_get_sock_hwaddr(int sockfd, uint8_t *hwaddr,
                                           size_t *len)
{
    int iface;
    if (sockutil_get_sock_iface(sockfd, &iface)) {
        return -1;
    }
    return sockutil_get_iface_hwaddr(iface, hwaddr, len);
}

#endif
