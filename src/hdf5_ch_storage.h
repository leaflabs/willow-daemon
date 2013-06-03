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
 * @file hdf5_ch_storage.h
 * @brief HDF5 channel storage backend
 * @see ch_storage.h
 */

#ifndef _SRC_HDF5_CHANNEL_STORAGE_H_
#define _SRC_HDF5_CHANNEL_STORAGE_H_

struct ch_storage;

/* Create new channel storage object; returns NULL on error. */
struct ch_storage *hdf5_ch_storage_alloc(const char *out_file_path,
                                         const char *dataset_name);

void hdf5_ch_storage_free(struct ch_storage *chns);

#endif
