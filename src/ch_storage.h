/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

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

#ifndef _SRC_CHANNEL_STORAGE_H_
#define _SRC_CHANNEL_STORAGE_H_

#include <stdint.h>
#include <stdlib.h>

struct ch_storage_ops;

struct ch_storage {
    const char *cs_path;
    const struct ch_storage_ops *ops;
    void *priv;
};

struct ch_storage_ops {
    int (*cs_open)(struct ch_storage*);
    int (*cs_close)(struct ch_storage*);
    int (*cs_datasync)(struct ch_storage*);

    /* FIXME cs_write doesn't feel right for HDF5 */
    ssize_t (*cs_write)(struct ch_storage*, uint16_t *ch_data, size_t len);
};

static inline int ch_storage_open(struct ch_storage *chns)
{
    return chns->ops->cs_open(chns);
}

static inline int ch_storage_close(struct ch_storage *chns)
{
    return chns->ops->cs_close(chns);
}

static inline int ch_storage_datasync(struct ch_storage *chns)
{
    return chns->ops->cs_datasync(chns);
}

static inline ssize_t ch_storage_write(struct ch_storage *chns,
                                       uint16_t *ch_data,
                                       size_t len)
{
    return chns->ops->cs_write(chns, ch_data, len);
}

#endif
