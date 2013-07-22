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
 * @file libsng/sng.c
 * @brief libsng routines
 *
 * This is intentionally a very simple interface, with a single global
 * socket file descriptor for communicating with the daemon. That's
 * fine because the daemon only allows a single control socket
 * connection at time of implementation.
 */

#include "sng.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "client_socket.h"
#include "sockutil.h"
#include "type_attrs.h"

/* Global daemon control socket */
static int daemon_sockfd = -1;

int sng_open_connection(const char *host, uint16_t port)
{
    daemon_sockfd = sockutil_get_tcp_connected_p(host, port);
    return daemon_sockfd == -1 ? -1 : 0;
}

int sng_close_connection(void)
{
    if (daemon_sockfd == -1) {
        errno = EBADF;
        return -1;
    }
    int ret = close(daemon_sockfd);
    if (ret == 0) {
        daemon_sockfd = -1;
    }
    return ret;
}

void sng_init_cmd_store(ControlCmdStore *store)
{
    ControlCmdStore tmp = CONTROL_CMD_STORE__INIT;
    memcpy(store, &tmp, sizeof(tmp));
}

int sng_store_samples(ControlCmdStore *store,
                      ControlResponse *response)
{
    uint8_t *send_buf = NULL;   /* protocol buffer we send */
    uint8_t *recv_buf = NULL;   /* protocol buffer we receive */
    ControlResponse *tmp = NULL; /* intermediate unpacked response */
    int ret = -1;
    if (daemon_sockfd == -1) {
        goto out;
    }

    /* Initialize the command protocol message we want to send the daemon. */
    ControlCommand cmd = CONTROL_COMMAND__INIT;
    cmd.has_type = 1;
    cmd.type = CONTROL_COMMAND__TYPE__STORE;
    cmd.store = store;

    /* Pack the command into a protocol buffer. */
    size_t len = control_command__get_packed_size(&cmd);
    if (len > CLIENT_CMD_MAX_SIZE) {
        /* Won't happen, but:
         *
         * If this protocol buffer is longer than the daemon supports,
         * we can't send it. (If we tried, the daemon would just shut
         * down the connection immediately). */
        goto out;
    }
    send_buf = malloc(len);
    if (!send_buf) {
        goto out;
    }
    control_command__pack(&cmd, send_buf);

    /* Send the command's length prefix, then its protocol buffer. */
    client_cmd_len_t cmdlen = (client_cmd_len_t)len;
    cmdlen = client_cmd_hton(cmdlen);
    if (send(daemon_sockfd, &cmdlen, sizeof(cmdlen), MSG_NOSIGNAL) == -1) {
        goto out;
    }
    if (send(daemon_sockfd, send_buf, len, MSG_NOSIGNAL) == -1) {
        goto out;
    }

    /* Get the response into our temporary object, then copy it into
     * the caller's buffer. */
    client_cmd_len_t resp_len;
    if (recv(daemon_sockfd, &resp_len, sizeof(resp_len), 0) == -1) {
        goto out;
    }
    resp_len = client_cmd_ntoh(resp_len);
    recv_buf = malloc(resp_len);
    if (!recv_buf) {
        goto out;
    }
    if (recv(daemon_sockfd, recv_buf, resp_len, 0) == -1) {
        goto out;
    }
    tmp = control_response__unpack(NULL, resp_len, recv_buf);
    if (!tmp) {
        goto out;
    }
    memcpy(response, tmp, sizeof(*response));

    /* Success. */
    ret = 0;
 out:
    if (send_buf) {
        free(send_buf);
    }
    if (recv_buf) {
        free(recv_buf);
    }
    if (tmp) {
        control_response__free_unpacked(tmp, NULL);
    }
    return ret;
}
