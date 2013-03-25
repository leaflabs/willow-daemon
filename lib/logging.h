/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

/**
 * @file logging.h
 * @brief Simple syslog wrapper
 *
 * Use this instead of calling syslog directly to allow the possiblity
 * of statically ensuring that low-priority log messages generate zero
 * code.
 *
 * Example usage:
 *
 *    // Call logging_init() once, at startup.
 *    //
 *    // - The first argument is the program's name; this isn't copied,
 *    //   so don't change the pointed-to string after calling this.
 *    //
 *    // - Messages of priority at least `level' will be emitted.
 *    //   Others will be filtered out. Level is one of the
 *    //   following, as specified by syslog.h: LOG_EMERG, LOG_ALERT,
 *    //   LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO,
 *    //   LOG_DEBUG.
 *    //
 *    // - If also_stderr is nonzero, messages are also emitted to
 *    //   stderr. (You must ensure STDERR_FILENO refers to a valid
 *    //   file descriptor.)
 *    logging_init("your program name", level, also_stderr);
 *
 *    // Use the LOG macro to log messages; fmt_string and varargs are
 *    // as with printf().
 *    LOG(level, fmt_string, ....);
 *
 *    // There are some other conveniences as well.
 *    log_EMERG("oh noes!");
 *    log_DEBUG("the %s has %d frobozzes", frobnicator, num_frobs);
 *
 *    // Call logging_fini() once, on shutdown.
 *    logging_fini();
 */

#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <syslog.h>

void logging_init(const char* program_name, int level, int also_stderr);

#define LOG(level, ...) syslog(level, __VA_ARGS__)
#define log_EMERG(...) syslog(LOG_EMERG, "EMERGENCY: " __VA_ARGS__)
#define log_ALERT(...) syslog(LOG_ALERT, "ALERT: " __VA_ARGS__)
#define log_CRIT(...) syslog(LOG_CRIT, "CRITICAL: " __VA_ARGS__)
#define log_ERR(...) syslog(LOG_ERR, "ERROR: " __VA_ARGS__)
#define log_WARNING(...) syslog(LOG_WARNING, "WARNING: " __VA_ARGS__)
#define log_NOTICE(...) syslog(LOG_NOTICE, "notice: " __VA_ARGS__)
#define log_INFO(...) syslog(LOG_INFO, "info: " __VA_ARGS__)
#define log_DEBUG(...) syslog(LOG_DEBUG, "debug: " __VA_ARGS__)

void logging_fini(void);

#endif
