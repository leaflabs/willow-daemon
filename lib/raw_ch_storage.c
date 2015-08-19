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

#include "raw_ch_storage.h"

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "type_attrs.h"
#include "ch_storage.h"
#include "raw_packets.h"
#include "logging.h"

struct raw_ch_data {
    int fd;
    mode_t mode;
};

static inline struct raw_ch_data* raw_ch_data(struct ch_storage *chns)
{
    struct raw_ch_data *data = chns->priv;
    return data;
}

static int raw_ch_open(struct ch_storage *chns, unsigned flags);
static int raw_ch_close(struct ch_storage *chns);
static int raw_ch_datasync(struct ch_storage *chns);
static int raw_ch_write(struct ch_storage *chns,
                        struct raw_pkt_fields*,
                        size_t);
static void raw_ch_free(struct ch_storage *chns);

static const struct ch_storage_ops raw_ch_storage_ops = {
    .ch_open = raw_ch_open,
    .ch_close = raw_ch_close,
    .ch_datasync = raw_ch_datasync,
    .ch_write = raw_ch_write,
    .ch_free = raw_ch_free,
};

struct ch_storage *raw_ch_storage_alloc(const char *out_file_path, mode_t mode)
{
    struct ch_storage *storage = malloc(sizeof(struct ch_storage));
    struct raw_ch_data *data = malloc(sizeof(struct raw_ch_data));
    if (!storage || !data) {
        free(storage);
        free(data);
        return NULL;
    }
    data->fd = -1;
    data->mode = mode;
    storage->ch_path = out_file_path;
    storage->ops = &raw_ch_storage_ops;
    storage->priv = data;
    return storage;
}

static void raw_ch_free(struct ch_storage *chns)
{
    free(raw_ch_data(chns));
    free(chns);
}

static int raw_ch_open(struct ch_storage *chns, unsigned flags)
{
    struct raw_ch_data *data = chns->priv;
    data->fd = open(chns->ch_path, flags, data->mode);
    return data->fd;
}

static int raw_ch_close(struct ch_storage *chns)
{
    return close(raw_ch_data(chns)->fd);
}

static int raw_ch_datasync(struct ch_storage *chns)
{
    return fdatasync(raw_ch_data(chns)->fd);
}

static int raw_ch_write(struct ch_storage *chns,
                        struct raw_pkt_fields *bsamp_data,
                        size_t n)
{
    ssize_t write_size;

    write_size = n*sizeof(uint8_t);
    if (write(raw_ch_data(chns)->fd, bsamp_data->ph_flags, write_size)
        != write_size) return -1;

    write_size = n*sizeof(uint32_t);
    if (write(raw_ch_data(chns)->fd, bsamp_data->sample_index, write_size)
        != write_size) return -1;

    write_size = n*sizeof(uint32_t);
    if (write(raw_ch_data(chns)->fd, bsamp_data->chip_live, write_size)
        != write_size) return -1;

    write_size = n*CH_STORAGE_NCHAN*sizeof(raw_samp_t);
    if (write(raw_ch_data(chns)->fd, bsamp_data->channel_data, write_size)
        != write_size) return -1;

    write_size = n*CH_STORAGE_NAUX*sizeof(raw_samp_t);
    if (write(raw_ch_data(chns)->fd, bsamp_data->aux_data, write_size)
        != write_size) return -1;

    return 0;
}
