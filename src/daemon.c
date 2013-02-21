/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

#include "daemon.h"

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/stat.h>

/* Fork, and return in the child process. The parent will die with
 * _exit() to avoid running any atexit() functions. */
static int fork_a_child(void)
{
    switch (fork()) {
    case -1: return -1;
    case 0: return 0;
    default: _exit(EXIT_SUCCESS);
    }
}

/* Return the largest possible file descriptor number.
 *
 * Tries to get the answer from sysconf(), but falls back on a
 * guess. */
#define MAX_FD_GUESS 4096 /* $ cat /proc/self/limits, Ubuntu 12.04 */
static int max_fd(void)
{
    int ret = sysconf(_SC_OPEN_MAX);
    return ret != -1 ? ret : MAX_FD_GUESS;
}

/* Make newfd be a copy of oldfd, unless ignore is non-null and
 * includes newfd. Returns 0 on success, -1 on failure. */
static int maybe_dup2(int oldfd, int newfd, fd_set *ignore)
{
    if (ignore && FD_ISSET(newfd, ignore)) {
        return 0;
    }
    return dup2(oldfd, newfd) == newfd ? 0 : -1;
}

int daemonize(fd_set *leave_open, int flags)
{
    assert(flags == 0);
    /* See TLPI sec. 37.2 for details on how this works. */

    /* Become a child of init. */
    if (fork_a_child() != 0) {
        return -1;
    }

    /* Make sure we're not session leader, to ensure we never
     * reacquire a controlling terminal (on platforms using System V
     * controlling terminal conventions, which includes Linux). */
    if (setsid() == -1) {
        return -1;
    }
    if (fork_a_child() != 0) {
        return -1;
    }

    /* Clear umask to ensure new files have requested permissions. */
    umask(0);

    /* Go to root directory, to allow caller's filesystem to unmount,
     * etc. */
    if (chdir("/") != 0) {
        return -1;
    }

    /* Close any files the user doesn't want us to leave open. */
    for (int fd = 0; fd < max_fd(); fd++) {
        if (leave_open && FD_ISSET(fd, leave_open)) {
            continue;
        }
        close(fd);
    }

    /* Reopen standard streams on /dev/null, unless asked not to. */
    int null_fd = open("/dev/null", O_RDWR);
    if ((null_fd == -1) ||
        (maybe_dup2(null_fd, STDIN_FILENO,  leave_open) == -1) ||
        (maybe_dup2(null_fd, STDOUT_FILENO, leave_open) == -1) ||
        (maybe_dup2(null_fd, STDERR_FILENO, leave_open) == -1)) {
        return -1;
    }

    /* Success! */
    return 0;
}
