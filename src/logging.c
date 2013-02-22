/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

#include "logging.h"

void logging_init(const char* program_name, int level, int also_stderr)
{
    openlog(program_name,
            LOG_ODELAY | LOG_NOWAIT | (also_stderr ? LOG_PERROR : 0),
            LOG_DAEMON);
    setlogmask(LOG_UPTO(level));
}

void logging_fini(void)
{
    closelog();
}
