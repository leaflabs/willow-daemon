/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

/**
 * @file raw_ch_storage.h
 * @brief Raw (i.e. write()-based) channel storage backend
 *
 * This is just for benchmarking.
 *
 * @see ch_storage.h
 */

#ifndef _SRC_RAW_CHANNEL_STORAGE_H_
#define _SRC_RAW_CHANNEL_STORAGE_H_

#include <stddef.h>
#include <sys/types.h>

#include "ch_storage.h"

/* Create new channel storage object; returns NULL on error. */
struct ch_storage *raw_ch_storage_alloc(const char *out_file_path,
                                        int flags, mode_t mode);

void raw_ch_storage_free(struct ch_storage *chns);

#endif
