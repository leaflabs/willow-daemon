/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

/**
 * @file hdf5_ch_storage.h
 * @brief HDF5 channel storage backend
 * @see ch_storage.h
 */

#ifndef _SRC_HDF5_CHANNEL_STORAGE_H_
#define _SRC_HDF5_CHANNEL_STORAGE_H_

#include <stddef.h>

#include "ch_storage.h"

/* Create new channel storage object; returns NULL on error. */
struct ch_storage *hdf5_ch_storage_alloc(const char *out_file_path,
                                         const char *dataset_name);

void hdf5_ch_storage_free(struct ch_storage *chns);

#endif
