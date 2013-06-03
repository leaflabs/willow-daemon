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
