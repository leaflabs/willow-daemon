/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "logging.h"

int sockutil_get_udp_socket(uint16_t port)
{
    int ret = -1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    char port_str[20];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo *ai_results;
    int gai_ret = getaddrinfo(NULL, port_str, &hints, &ai_results);
    if (gai_ret != 0) {
        // If getaddrinfo() fails, we might try falling back on
        // calling socket(AF_INET, SOCK_DGRAM, 0) ourselves to try to
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
        if (bind(sckt, arp->ai_addr, arp->ai_addrlen) == -1) {
            close(sckt);
            continue;
        }

        // Success!
        ret = sckt;
        break;
    }

    freeaddrinfo(ai_results);

    log_NOTICE("created UDP socket on port %u", port);
    return ret;
}
