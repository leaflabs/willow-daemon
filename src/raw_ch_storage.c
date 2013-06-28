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

struct raw_cs_data {
    int fd;
    int flags;
    mode_t mode;
};

static inline struct raw_cs_data* raw_cs_data(struct ch_storage *chns)
{
    struct raw_cs_data *data = chns->priv;
    return data;
}

static int raw_cs_open(struct ch_storage *chns);
static int raw_cs_close(struct ch_storage *chns);
static int raw_cs_datasync(struct ch_storage *chns);
static ssize_t raw_cs_write(struct ch_storage *chns, struct raw_pkt_bsmp*);

static const struct ch_storage_ops raw_ch_storage_ops = {
    .cs_open = raw_cs_open,
    .cs_close = raw_cs_close,
    .cs_datasync = raw_cs_datasync,
    .cs_write = raw_cs_write,
};

struct ch_storage *raw_ch_storage_alloc(const char *out_file_path,
                                        int flags, mode_t mode)
{
    struct ch_storage *storage = malloc(sizeof(struct ch_storage));
    struct raw_cs_data *data = malloc(sizeof(struct raw_cs_data));
    if (!storage || !data) {
        free(storage);
        free(data);
        return NULL;
    }
    data->fd = -1;
    data->flags = flags;
    data->mode = mode;
    storage->cs_path = out_file_path;
    storage->ops = &raw_ch_storage_ops;
    storage->priv = data;
    return storage;
}

void raw_ch_storage_free(struct ch_storage *chns)
{
    free(raw_cs_data(chns));
    free(chns);
}

static int raw_cs_open(struct ch_storage *chns)
{
    struct raw_cs_data *data = chns->priv;
    data->fd = open(chns->cs_path, data->flags, data->mode);
    return data->fd;
}

static int raw_cs_close(struct ch_storage *chns)
{
    return close(raw_cs_data(chns)->fd);
}

static int raw_cs_datasync(struct ch_storage *chns)
{
    return fdatasync(raw_cs_data(chns)->fd);
}

static ssize_t raw_cs_write(struct ch_storage *chns, struct raw_pkt_bsmp *bsmp)
{
    return write(raw_cs_data(chns)->fd, bsmp, sizeof(*bsmp));
}
