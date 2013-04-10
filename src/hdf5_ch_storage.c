/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */
/* TODO: finish implementing these */

#include "hdf5_ch_storage.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <hdf5.h>

#include "logging.h"
#include "type_attrs.h"

#define IS_LITTLE_ENDIAN (1 == *(unsigned char *)&(const int){1})
#define HOST_H5_ORDER (IS_LITTLE_ENDIAN ? H5T_ORDER_LE : H5T_ORDER_BE)

static int hdf5_cs_open(struct ch_storage *chns);
static int hdf5_cs_close(struct ch_storage *chns);
static int hdf5_cs_datasync(struct ch_storage *chns);
static ssize_t hdf5_cs_write(struct ch_storage *chns, uint16_t *ch_data,
                             size_t len);

static const struct ch_storage_ops hdf5_ch_storage_ops = {
    .cs_open = hdf5_cs_open,
    .cs_close = hdf5_cs_close,
    .cs_datasync = hdf5_cs_datasync,
    .cs_write = hdf5_cs_write,
};

struct h5_cs_data {
    const char *dset_name;      /* dataset name */
    hid_t h5_file;              /* HDF5 file type */
    hid_t h5_dspace;            /* data space */
    hid_t h5_dtype;             /* data type */
    hid_t h5_dset;              /* data set */
};

static inline struct h5_cs_data* h5_data(struct ch_storage *chns)
{
    struct h5_cs_data *data = chns->priv;
    return data;
}

static void h5_ch_data_init(struct h5_cs_data *data, const char *dset_name)
{
    data->dset_name = dset_name;
    data->h5_file = -1;
    data->h5_dspace = -1;
    data->h5_dtype = -1;
    data->h5_dset = -1;
}

static int h5_ch_data_teardown(struct h5_cs_data *data)
{
    int ret = 0;
    if (data->h5_dset >= 0 && H5Dclose(data->h5_dset) < 0) {
        ret = -1;
    }
    if (data->h5_dtype >= 0 && H5Tclose(data->h5_dtype) < 0) {
        ret = -1;
    }
    if (data->h5_dspace >= 0 && H5Sclose(data->h5_dspace) < 0) {
        ret = -1;
    }
    if (data->h5_file >= 0 && H5Fclose(data->h5_file) < 0) {
        ret = -1;
    }
    return ret;
}

struct ch_storage *hdf5_ch_storage_alloc(const char *out_file_path,
                                         const char *dataset_name)
{
    struct ch_storage *storage = malloc(sizeof(struct ch_storage));
    struct h5_cs_data *data = malloc(sizeof(struct h5_cs_data));
    if (!storage || !data) {
        free(storage);
        free(data);
        return NULL;
    }
    h5_ch_data_init(data, dataset_name);
    storage->cs_path = out_file_path;
    storage->ops = &hdf5_ch_storage_ops;
    storage->priv = data;
    return storage;
}

void hdf5_ch_storage_free(struct ch_storage *chns)
{
    free(h5_data(chns));
    free(chns);
}

#define O_LOG_ERR(failure, chns)                                \
    log_ERR("can't open %s: error on %s", chns->cs_path, failure);
static int hdf5_cs_open(struct ch_storage *chns)
{
#if 1
    log_WARNING("XXXXXXXXX "
                "%s skipping open of %s (not implemented) "
                "XXXXXXXXX",
                __func__, chns->cs_path);
    errno = EIO;
    return -1;
#else  /* FIXME finish this up */
    struct h5_cs_data tmp;
    h5_ch_data_init(&tmp, h5_data(chns)->dset_name);

    tmp.h5_file = H5Fcreate(chns->cs_path, H5F_ACC_TRUNC, H5P_DEFAULT,
                            H5P_DEFAULT);
    if (tmp.h5_file < 0) {
        O_LOG_ERR("HDF5 file", chns);
        goto fail;
    }

    const hsize_t cur_dim = 0, max_dim = H5S_UNLIMITED;
    tmp.h5_dspace = H5Screate_simple(1, &cur_dim, &max_dim);
    if (tmp.h5_dspace < 0) {
        O_LOG_ERR("data space", chns);
        goto fail;
    }

    assert(sizeof(unsigned short) == 2);
    tmp.h5_dtype = H5Tcopy(H5T_NATIVE_USHORT);
    if (tmp.h5_dtype < 0) {
        O_LOG_ERR("data type", chns);
        goto fail;
    }

    herr_t err = H5Tset_order(tmp.h5_dtype, HOST_H5_ORDER);
    if (err < 0) {
        O_LOG_ERR("byte order", chns);
        goto fail;
    }

    tmp.h5_dset = H5Dcreate(tmp.h5_file, tmp.dset_name, tmp.h5_dtype,
                            tmp.h5_dspace, H5P_DEFAULT);
    if (tmp.h5_dset < 0) {
        O_LOG_ERR("data set", chns);
        goto fail;
    }

    /* Success! */
    memcpy(h5_data(chns), &tmp, sizeof(tmp));
    return 0;
 fail:
    /* Free any resources acquired in tmp. */
    if (h5_ch_data_teardown(&tmp) == -1) {
        log_ERR("HDF5 teardown failed");
    }
    /* TODO: if H5Fcreate created a file, should we notice and unlink here? */
    return -1;
#endif
}
#undef O_LOG_ERR

static int hdf5_cs_close(struct ch_storage *chns)
{
    return h5_ch_data_teardown(h5_data(chns));
}

static int hdf5_cs_datasync(struct ch_storage *chns)
{
    return H5Fflush(h5_data(chns)->h5_file, H5F_SCOPE_LOCAL);
}

static ssize_t hdf5_cs_write(struct ch_storage *chns,
                             uint16_t *ch_data,
                             size_t len)
{
    /* TODO */
    log_WARNING("XXXXXXXXX "
                "%s skipping write of "
                "%zu bytes from %p to %s (not implemented) "
                "XXXXXXXXX",
                __func__, len, (void*)ch_data, chns->cs_path);
    errno = EIO;
    return -1;
}
