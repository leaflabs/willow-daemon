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
 * @file ch_storage.h
 * @brief Object orientation for channel storage
 *
 * This looks a lot like a wrapper for the normal filesystem API. It
 * basically is, which, yes, does kind of suck. There's not much that
 * can be done about that, given that we want to abstract away whether
 * or not we're e.g. using HDF5 or write(), and that HDF5's library
 * hides the fd from you behind a hid_t.
 */

#ifndef _LIB_CHANNEL_STORAGE_H_
#define _LIB_CHANNEL_STORAGE_H_

#include <stdint.h>
#include <stdlib.h>

struct ch_storage_ops;
struct raw_pkt_bsmp;

struct ch_storage {
    const char *ch_path;
    const struct ch_storage_ops *ops;
    void *priv;
};

struct ch_storage_ops {
    int (*ch_open)(struct ch_storage*, unsigned flags);
    int (*ch_close)(struct ch_storage*);
    int (*ch_datasync)(struct ch_storage*);
    int (*ch_write)(struct ch_storage*, const struct raw_pkt_bsmp *bsamps,
                    size_t nsamps);
    void (*ch_free)(struct ch_storage*);
};

static inline int ch_storage_open(struct ch_storage *chns, unsigned flags)
{
    return chns->ops->ch_open(chns, flags);
}

static inline int ch_storage_close(struct ch_storage *chns)
{
    return chns->ops->ch_close(chns);
}

static inline int ch_storage_datasync(struct ch_storage *chns)
{
    return chns->ops->ch_datasync(chns);
}

static inline int ch_storage_write(struct ch_storage *chns,
                                   const struct raw_pkt_bsmp *bsamps,
                                   size_t nsamps)
{
    return chns->ops->ch_write(chns, bsamps, nsamps);
}

static inline void ch_storage_free(struct ch_storage *chns)
{
    void (*f)(struct ch_storage*) = chns->ops->ch_free;
    f(chns);
}

#endif
