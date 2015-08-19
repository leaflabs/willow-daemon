/* Copyright (c) 2013 LeafLabs, LLC.
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.  *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Note: error logging must be handled externally, using the HDF5
 * error routines (namespace H5E*).
 */

#include "hdf5_ch_storage.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <hdf5.h>

#include "logging.h"
#include "type_attrs.h"
#include "ch_storage.h"
#include "raw_packets.h"


#define DSET_EXTEND_FACTOR 1.75 /* TODO tune this knob */
#define RANK 1                  /* we store as an array of board samples */
#define IS_LITTLE_ENDIAN (1 == *(unsigned char *)&(const int){1})
#define HOST_H5_ORDER (IS_LITTLE_ENDIAN ? H5T_ORDER_LE : H5T_ORDER_BE)
#define COOKIE_H5_TYPE H5T_NATIVE_UINT64

static int hdf5_ch_open(struct ch_storage *chns, unsigned flags);
static int hdf5_ch_close(struct ch_storage *chns);
static int hdf5_ch_datasync(struct ch_storage *chns);
static int hdf5_ch_write(struct ch_storage*, struct raw_pkt_fields*, size_t);
static void hdf5_ch_free(struct ch_storage *chns);

static const struct ch_storage_ops hdf5_ch_storage_ops = {
    .ch_open = hdf5_ch_open,
    .ch_close = hdf5_ch_close,
    .ch_datasync = hdf5_ch_datasync,
    .ch_write = hdf5_ch_write,
    .ch_free = hdf5_ch_free,
};

/* Convert an unsigned integer (or unsigned type) to the corresponding
 * HDF5 type ID. */
#define TO_H5_UTYPE(x)                                  \
    ({                                                  \
        hid_t __h5_utype = -1;                          \
        size_t __x_size = sizeof(x);                    \
        if (__x_size == 1) {                            \
            __h5_utype = H5T_NATIVE_UINT8;              \
        } else if (__x_size == 2) {                     \
            __h5_utype = H5T_NATIVE_UINT16;             \
        } else if (__x_size == 4) {                     \
            __h5_utype = H5T_NATIVE_UINT32;             \
        } else if (__x_size == 8) {                     \
            __h5_utype = H5T_NATIVE_UINT64;             \
        } else {                                        \
            assert(0);                                  \
        }                                               \
        __h5_utype;                                     \
    })

/* Dataset attributes and their names -- the numbers index into
 * h5_ch_data->h5_attrs, and aren't necessarily the same as their
 * indices in an HDF5 file. */
#define H5_ATTR_MTYPE 0         /* mtype (==RAW_MTYPE_BSMP) */
#define H5_ATTR_BOARD_ID 1      /* board identifier */
#define H5_ATTR_PVERS 2         /* protocol version */
#define H5_ATTR_COOKIE 3        /* experiment cookie */
#define H5_ATTR_MTYPE_NAME "raw_mtype"
#define H5_ATTR_BOARD_ID_NAME "board_id"
#define H5_ATTR_PVERS_NAME "raw_proto_vers"
#define H5_ATTR_COOKIE_NAME "experiment_cookie"
#define H5_NATTRS (H5_ATTR_COOKIE + 1)

struct h5_ch_data {
    const char *dset_name;      /* dataset name */
    hid_t h5_file;              /* HDF5 file type */
    hid_t h5_dspace;            /* data space */
    hid_t h5_arrtype;           /* sample array (within bsamp) data type */
    hid_t h5_dtype;             /* board sample data type */
    hid_t h5_dset;              /* data set */
    hid_t h5_dset_ph_flags;       /* ph_flags data set */
    hid_t h5_dset_sample_index;       /* sample_index data set */
    hid_t h5_dset_chip_live;       /* chip_live data set */
    hid_t h5_dset_channel_data;      /* channel_data data set */
    hid_t h5_dset_aux_data;        /* aux_data data set */
    hsize_t h5_dset_off;        /* current dataset write offset */
    hsize_t h5_dset_size;       /* current dataset size */
    hid_t h5_attr_dspace;       /* attribute data space */
    hid_t h5_attrs[H5_NATTRS];  /* dataset-wide attributes (see H5_ATTR_*) */

    /* Some attributes can't be set until we get the first board
     * sample (e.g. experiment cookie). This field indicates whether
     * those fields have been set yet. */
    int h5_need_attrs;

    uint32_t h5_debug_board_id;
};

double hdf5_diffTimeSpec(struct timespec ts1, struct timespec ts2)
{
    /* ts1 is first timepoint, ts2 is second */
    /* returns seconds as double */

    double diff;

    diff = (double)(ts2.tv_sec-ts1.tv_sec) + ((double)(ts2.tv_nsec-ts1.tv_nsec))*1e-9;

    return diff;
}

static inline struct h5_ch_data* h5_data(struct ch_storage *chns)
{
    struct h5_ch_data *data = chns->priv;
    return data;
}

static void h5_ch_data_init(struct h5_ch_data *data, const char *dset_name)
{
    /*
     * These could be partitioned into init-only and
     * life-of-ch_storage groups, but it doesn't seem worth the effort
     * right now.
     */
    data->dset_name = dset_name;
    data->h5_file = -1;
    data->h5_dspace = -1;
    data->h5_arrtype = -1;
    data->h5_dtype = -1;
    data->h5_dset = -1;
    data->h5_dset_off = 0;
    data->h5_dset_size = 0;
    data->h5_attr_dspace = -1;
    for (size_t i = 0; i < H5_NATTRS; i++) {
        data->h5_attrs[i] = -1;
    }
    data->h5_need_attrs = 1;
    data->h5_debug_board_id = 0;
}

static int h5_ch_data_teardown(struct h5_ch_data *cfg_data)
{
    int ret = 0;

    if (cfg_data->h5_dset_ph_flags >= 0 && H5Dclose(cfg_data->h5_dset_ph_flags) < 0) {
        ret = -1;
    }

    if (cfg_data->h5_dset_sample_index >= 0 && H5Dclose(cfg_data->h5_dset_sample_index) < 0) {
        ret = -1;
    }

    if (cfg_data->h5_dset_chip_live >= 0 && H5Dclose(cfg_data->h5_dset_chip_live) < 0) {
        ret = -1;
    }

    if (cfg_data->h5_dset_channel_data >= 0 && H5Dclose(cfg_data->h5_dset_channel_data) < 0) {
        ret = -1;
    }

    if (cfg_data->h5_dset_aux_data >= 0 && H5Dclose(cfg_data->h5_dset_aux_data) < 0) {
        ret = -1;
    }

    if (cfg_data->h5_file >= 0 && H5Fclose(cfg_data->h5_file) < 0) {
        ret = -1;
    }
    return ret;
}

struct ch_storage *hdf5_ch_storage_alloc(const char *out_file_path,
                                         const char *dataset_name)
{
    struct ch_storage *storage = malloc(sizeof(struct ch_storage));
    struct h5_ch_data *data = malloc(sizeof(struct h5_ch_data));
    if (!storage || !data) {
        free(storage);
        free(data);
        return NULL;
    }
    if (!dataset_name) {
        dataset_name = "wired-dataset";
    }
    h5_ch_data_init(data, dataset_name);
    storage->ch_path = out_file_path;
    storage->ops = &hdf5_ch_storage_ops;
    storage->priv = data;
    return storage;
}

static void hdf5_ch_free(struct ch_storage *chns)
{
    free(h5_data(chns));
    free(chns);
}

/* Make the various data sets */
static hid_t hdf5_create_dsets(struct h5_ch_data* cfg_data)
{
    int ret = -1;

    hid_t dset_tmp = -1;
    hsize_t cur_dim, max_dim;
    hid_t dspace_tmp;
    hid_t cprops_tmp;
    hsize_t chunk_scalar, chunk_channel_data, chunk_aux_data;

    int chunk_nsamp = 1000; /* TODO tune this */
    chunk_scalar = chunk_nsamp;
    chunk_channel_data = chunk_nsamp*CH_STORAGE_NCHAN;
    chunk_aux_data = chunk_nsamp*CH_STORAGE_NAUX;

    cur_dim = 0;
    max_dim = H5S_UNLIMITED;

    /* ph_flags */
    
    dspace_tmp = H5Screate_simple(1, &cur_dim, &max_dim);
    cprops_tmp = H5Pcreate(H5P_DATASET_CREATE);

    if ( (dspace_tmp < 0) || (cprops_tmp < 0) ) {
        goto fail;
    }

    if (H5Pset_chunk(cprops_tmp, 1, &chunk_scalar) < 0) {
        goto fail;
    }

    dset_tmp = H5Dcreate2(cfg_data->h5_file, "ph_flags", H5T_NATIVE_UCHAR,
                     dspace_tmp, H5P_DEFAULT, cprops_tmp, H5P_DEFAULT);
    if (dset_tmp >= 0) {
        cfg_data->h5_dset_ph_flags = dset_tmp;
    } else {
        goto fail;
    }

    /* sample_index */
    
    dspace_tmp = H5Screate_simple(1, &cur_dim, &max_dim);
    cprops_tmp = H5Pcreate(H5P_DATASET_CREATE);

    if ( (dspace_tmp < 0) || (cprops_tmp < 0) ) {
        goto fail;
    }

    if (H5Pset_chunk(cprops_tmp, 1, &chunk_scalar) < 0) {
        goto fail;
    }

    dset_tmp = H5Dcreate2(cfg_data->h5_file, "sample_index", H5T_NATIVE_UINT,
                     dspace_tmp, H5P_DEFAULT, cprops_tmp, H5P_DEFAULT);
    if (dset_tmp >= 0) {
        cfg_data->h5_dset_sample_index = dset_tmp;
    } else {
        goto fail;
    }

    /* chip_live*/
    
    dspace_tmp = H5Screate_simple(1, &cur_dim, &max_dim);
    cprops_tmp = H5Pcreate(H5P_DATASET_CREATE);

    if ( (dspace_tmp < 0) || (cprops_tmp < 0) ) {
        goto fail;
    }

    if (H5Pset_chunk(cprops_tmp, 1, &chunk_scalar) < 0) {
        goto fail;
    }

    dset_tmp = H5Dcreate2(cfg_data->h5_file, "chip_live", H5T_NATIVE_UINT,
                     dspace_tmp, H5P_DEFAULT, cprops_tmp, H5P_DEFAULT);
    if (dset_tmp >= 0) {
        cfg_data->h5_dset_chip_live = dset_tmp;
    } else {
        goto fail;
    }

    /* channel_data */
    
    dspace_tmp = H5Screate_simple(1, &cur_dim, &max_dim);
    cprops_tmp = H5Pcreate(H5P_DATASET_CREATE);

    if ( (dspace_tmp < 0) || (cprops_tmp < 0) ) {
        goto fail;
    }

    if (H5Pset_chunk(cprops_tmp, 1, &chunk_channel_data) < 0) {
        goto fail;
    }

    dset_tmp = H5Dcreate2(cfg_data->h5_file, "channel_data", H5T_NATIVE_USHORT,
                     dspace_tmp, H5P_DEFAULT, cprops_tmp, H5P_DEFAULT);
    if (dset_tmp >= 0) {
        cfg_data->h5_dset_channel_data = dset_tmp;
    } else {
        goto fail;
    }

    /* aux_data*/
    
    dspace_tmp = H5Screate_simple(1, &cur_dim, &max_dim);
    cprops_tmp = H5Pcreate(H5P_DATASET_CREATE);

    if ( (dspace_tmp < 0) || (cprops_tmp < 0) ) {
        goto fail;
    }

    if (H5Pset_chunk(cprops_tmp, 1, &chunk_aux_data) < 0) {
        goto fail;
    }

    dset_tmp = H5Dcreate2(cfg_data->h5_file, "aux_data", H5T_NATIVE_USHORT,
                     dspace_tmp, H5P_DEFAULT, cprops_tmp, H5P_DEFAULT);
    if (dset_tmp >= 0) {
        cfg_data->h5_dset_aux_data = dset_tmp;
    } else {
        goto fail;
    }

    ret = 0; // success!
    fail:
        H5Pclose(cprops_tmp);
        H5Sclose(dspace_tmp);
        return ret;
}

static int hdf5_ch_open(struct ch_storage *chns, unsigned flags)
{
    struct h5_ch_data tmp;
    h5_ch_data_init(&tmp, h5_data(chns)->dset_name); /* initialize defaults */

    /* disable chunk caching for the file */
    hid_t fapl = H5Pcreate(H5P_FILE_ACCESS);
    H5Pset_cache(fapl, 0,0,0,0);

    //tmp.h5_file = H5Fcreate(chns->ch_path, flags, H5P_DEFAULT, H5P_DEFAULT);
    tmp.h5_file = H5Fcreate(chns->ch_path, flags, H5P_DEFAULT, fapl);
    if (tmp.h5_file < 0) {
        goto fail;
    }

    if (hdf5_create_dsets(&tmp) < 0) {
        goto fail;
    }

    memcpy(h5_data(chns), &tmp, sizeof(tmp)); /* Success! */
    return 0;

 fail:
    if (h5_ch_data_teardown(&tmp) == -1) {
        log_ERR("HDF5 teardown failed");
    }
    if (H5Fis_hdf5(chns->ch_path) > 0 && unlink(chns->ch_path) == -1) {
        log_ERR("can't unlink %s: %m", chns->ch_path);
    }
    return -1;
}

static int hdf5_ch_truncate(struct h5_ch_data* cfg_data) {

    hsize_t final_size = cfg_data->h5_dset_off;
    hsize_t final_size_channel_data = final_size*CH_STORAGE_NCHAN;
    hsize_t final_size_aux_data = final_size*CH_STORAGE_NAUX;

    herr_t ret;

    if ((ret = H5Dset_extent(cfg_data->h5_dset_ph_flags, &final_size)) < 0) {
        goto fail;
    }
    if ((ret = H5Dset_extent(cfg_data->h5_dset_sample_index, &final_size)) < 0) {
        goto fail;
    }
    if ((ret = H5Dset_extent(cfg_data->h5_dset_chip_live, &final_size)) < 0) {
        goto fail;
    }
    if ((ret = H5Dset_extent(cfg_data->h5_dset_channel_data, &final_size_channel_data)) < 0) {
        goto fail;
    }
    if ((ret = H5Dset_extent(cfg_data->h5_dset_aux_data, &final_size_aux_data)) < 0 ) {
        goto fail;
    }

    fail:
        return ret;
}

static int hdf5_ch_close(struct ch_storage *chns)
{
    struct h5_ch_data *data = h5_data(chns);
    if (hdf5_ch_truncate(data) < 0) {
        log_ERR("Can't truncate datasets on close; sample data in "
                "dataset after offset will be garbage");
    }
    return h5_ch_data_teardown(h5_data(chns));
}

static int hdf5_ch_datasync(struct ch_storage *chns)
{
    return H5Fflush(h5_data(chns)->h5_file, H5F_SCOPE_LOCAL);
}

/* Increase the size of the datasets to make room for more samples. */
static herr_t hdf5_extend(struct h5_ch_data* cfg_data, hsize_t minsize)
{

    hsize_t newsize, newsize_channel_data, newsize_aux_data;

    if (cfg_data->h5_dset_size) {
        newsize = (double)cfg_data->h5_dset_size * DSET_EXTEND_FACTOR + 0.5;
    } else {
        newsize = 1;
    }

    if (newsize < minsize) {
        newsize = minsize;
    }

    newsize_channel_data = newsize*CH_STORAGE_NCHAN;
    newsize_aux_data= newsize*CH_STORAGE_NAUX;

    herr_t ret = -1;

    /* extend each dataset */

    if (H5Dset_extent(cfg_data->h5_dset_ph_flags, &newsize) < 0) {
        goto fail;
    }

    if (H5Dset_extent(cfg_data->h5_dset_sample_index, &newsize) < 0) {
        goto fail;
    }

    if (H5Dset_extent(cfg_data->h5_dset_chip_live, &newsize) < 0) {
        goto fail;
    }

    if (H5Dset_extent(cfg_data->h5_dset_channel_data, &newsize_channel_data) < 0) {
        goto fail;
    }

    if (H5Dset_extent(cfg_data->h5_dset_aux_data, &newsize_aux_data) < 0) {
        goto fail;
    }

    /* done */

    cfg_data->h5_dset_size = newsize;
    ret = 0;
    fail:
        return ret;

}

static int hdf5_ch_write_attrs(struct h5_ch_data* cfg_data,
                                 struct raw_pkt_fields* bsamp_data)
{
    int ret = -1;

    hid_t scalar_space, root_group, attr_tmp;
    hsize_t dim;
    herr_t status;

    root_group = H5Gopen2(cfg_data->h5_file, "/", H5P_DEFAULT);

    /* all attrs are scalars */
    dim = 1;
    scalar_space = H5Screate_simple(1, &dim, NULL);

    /* board_id */
    attr_tmp = H5Acreate(root_group, "board_id", H5T_NATIVE_UINT, scalar_space,
                     H5P_DEFAULT, H5P_DEFAULT);
    if (attr_tmp < 0) goto fail;
    status = H5Awrite(attr_tmp, H5T_NATIVE_UINT, &(bsamp_data->board_id));
    if (status < 0) goto fail;
    H5Aclose(attr_tmp);

    /* experiment_cookie */
    attr_tmp = H5Acreate(root_group, "experiment_cookie", H5T_NATIVE_ULONG,
                         scalar_space, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_tmp < 0) goto fail;
    status = H5Awrite(attr_tmp, H5T_NATIVE_ULONG,
                      &(bsamp_data->experiment_cookie));
    if (status < 0) goto fail;
    H5Aclose(attr_tmp);

    /* raw_mtype */
    attr_tmp = H5Acreate(root_group, "raw_mtype", H5T_NATIVE_UCHAR,
                         scalar_space, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_tmp < 0) goto fail;
    status = H5Awrite(attr_tmp, H5T_NATIVE_UCHAR,
                      &(bsamp_data->raw_mtype));
    if (status < 0) goto fail;
    H5Aclose(attr_tmp);

    /* raw_proto_vers*/
    attr_tmp = H5Acreate(root_group, "raw_proto_vers", H5T_NATIVE_UCHAR,
                         scalar_space, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_tmp < 0) goto fail;
    status = H5Awrite(attr_tmp, H5T_NATIVE_UCHAR,
                      &(bsamp_data->raw_proto_vers));
    if (status < 0) goto fail;
    H5Aclose(attr_tmp);

    ret = 0;
    fail:
        H5Gclose(root_group);
        H5Sclose(scalar_space);
        return ret;

}

static int hdf5_ch_write_ph_flags(struct h5_ch_data* cfg_data,
                                 struct raw_pkt_fields* bsamp_data,
                                 size_t nsamps)
{
    int ret = -1;

    hid_t filespace = -1;
    hid_t memspace = -1;
    hsize_t datasize = nsamps;
    memspace = H5Screate_simple(1, &datasize, NULL);
    filespace = H5Dget_space(cfg_data->h5_dset_ph_flags);
    if ( (memspace < 0) || (filespace < 0) ) {
        goto fail;
    }

    hsize_t slabdim = nsamps;
    if (H5Sselect_hyperslab(filespace, H5S_SELECT_SET, &cfg_data->h5_dset_off,
                            NULL, &slabdim, NULL) < 0) {
        goto fail;
    }
    if (H5Dwrite(cfg_data->h5_dset_ph_flags, H5T_NATIVE_UCHAR,
                 memspace, filespace, H5P_DEFAULT, bsamp_data->ph_flags) < 0) {
        goto fail;
    }

    ret = 0; // success!
    fail:
        H5Sclose(filespace);
        H5Sclose(memspace);
        return ret;
}

static int hdf5_ch_write_sample_index(struct h5_ch_data* cfg_data,
                                 struct raw_pkt_fields* bsamp_data,
                                 size_t nsamps)
{
    int ret = -1;

    hid_t filespace = -1;
    hid_t memspace = -1;
    hsize_t datasize = nsamps;
    memspace = H5Screate_simple(1, &datasize, NULL);
    filespace = H5Dget_space(cfg_data->h5_dset_sample_index);
    if ( (memspace < 0) || (filespace < 0) ) {
        goto fail;
    }

    hsize_t slabdim = nsamps;
    if (H5Sselect_hyperslab(filespace, H5S_SELECT_SET, &cfg_data->h5_dset_off,
                            NULL, &slabdim, NULL) < 0) {
        goto fail;
    }
    if (H5Dwrite(cfg_data->h5_dset_sample_index, H5T_NATIVE_UINT,
                 memspace, filespace, H5P_DEFAULT, bsamp_data->sample_index) < 0) {
        goto fail;
    }

    ret = 0; // success!
    fail:
        H5Sclose(filespace);
        H5Sclose(memspace);
        return ret;
}

static int hdf5_ch_write_chip_live(struct h5_ch_data* cfg_data,
                                 struct raw_pkt_fields* bsamp_data,
                                 size_t nsamps)
{
    int ret = -1;

    hid_t filespace = -1;
    hid_t memspace = -1;
    hsize_t datasize = nsamps;
    memspace = H5Screate_simple(1, &datasize, NULL);
    filespace = H5Dget_space(cfg_data->h5_dset_chip_live);
    if ( (memspace < 0) || (filespace < 0) ) {
        goto fail;
    }

    hsize_t slabdim = nsamps;
    if (H5Sselect_hyperslab(filespace, H5S_SELECT_SET, &cfg_data->h5_dset_off,
                            NULL, &slabdim, NULL) < 0) {
        goto fail;
    }
    if (H5Dwrite(cfg_data->h5_dset_chip_live, H5T_NATIVE_UINT,
                 memspace, filespace, H5P_DEFAULT, bsamp_data->chip_live) < 0) {
        goto fail;
    }

    ret = 0; // success!
    fail:
        H5Sclose(filespace);
        H5Sclose(memspace);
        return ret;
}

static int hdf5_ch_write_channel_data(struct h5_ch_data* cfg_data,
                                 struct raw_pkt_fields* bsamp_data,
                                 size_t nsamps)
{
    int ret = -1;

    hid_t filespace = -1;
    hid_t memspace = -1;
    hsize_t datasize_unwound = nsamps*CH_STORAGE_NCHAN;
    memspace = H5Screate_simple(1, &datasize_unwound, NULL);
    filespace = H5Dget_space(cfg_data->h5_dset_channel_data);
    if ( (memspace < 0) || (filespace < 0) ) {
        goto fail;
    }

    hsize_t slaboffset = cfg_data->h5_dset_off*CH_STORAGE_NCHAN;
    hsize_t slabdim = nsamps*CH_STORAGE_NCHAN;
    if (H5Sselect_hyperslab(filespace, H5S_SELECT_SET, &slaboffset,
                            NULL, &slabdim, NULL) < 0) {
        goto fail;
    }
    if (H5Dwrite(cfg_data->h5_dset_channel_data, H5T_NATIVE_USHORT,
                 memspace, filespace, H5P_DEFAULT, bsamp_data->channel_data) < 0) {
        goto fail;
    }

    ret = 0; // success!
    fail:
        H5Sclose(filespace);
        H5Sclose(memspace);
        return ret;
}

static int hdf5_ch_write_aux_data(struct h5_ch_data* cfg_data,
                                 struct raw_pkt_fields* bsamp_data,
                                 size_t nsamps)
{
    int ret = -1;

    hid_t filespace = -1;
    hid_t memspace = -1;
    hsize_t datasize_unwound = nsamps*CH_STORAGE_NAUX;
    memspace = H5Screate_simple(1, &datasize_unwound, NULL);
    filespace = H5Dget_space(cfg_data->h5_dset_aux_data);
    if ( (memspace < 0) || (filespace < 0) ) {
        goto fail;
    }

    hsize_t slaboffset = cfg_data->h5_dset_off*CH_STORAGE_NAUX;
    hsize_t slabdim = nsamps*CH_STORAGE_NAUX;
    if (H5Sselect_hyperslab(filespace, H5S_SELECT_SET, &slaboffset,
                            NULL, &slabdim, NULL) < 0) {
        goto fail;
    }
    if (H5Dwrite(cfg_data->h5_dset_aux_data, H5T_NATIVE_USHORT,
                 memspace, filespace, H5P_DEFAULT, bsamp_data->aux_data) < 0) {
        goto fail;
    }

    ret = 0; // success!
    fail:
        H5Sclose(filespace);
        H5Sclose(memspace);
        return ret;
}

static int hdf5_ch_write(struct ch_storage *chns,
                         struct raw_pkt_fields* bsamp_data,
                         size_t nsamps)
{
    int ret = -1;

    struct h5_ch_data *cfg_data = h5_data(chns);
    if (!nsamps) {
        return 0;
    }

    /* Take care of "first write" bookkeeping. */
    if (cfg_data->h5_need_attrs) {
        cfg_data->h5_debug_board_id = bsamp_data->board_id;
        //hdf5_init_exp_attrs(chns, bsamps);  // forget the attributes for not
        if (hdf5_ch_write_attrs(cfg_data, bsamp_data) < 0) {
            goto fail;
        }
        cfg_data->h5_need_attrs = 0;
    }

    /* Sanity-check that we're not getting packets from a different board. */
    assert(bsamp_data->board_id == cfg_data->h5_debug_board_id);

    /* If we're getting more board samples than will fit, we need to
     * extend the dataset. */
    hsize_t next_offset = cfg_data->h5_dset_off + nsamps;
    if (next_offset >= cfg_data->h5_dset_size) {
        if (hdf5_extend(cfg_data, next_offset) < 0) {
            log_ERR("Can't increase space allocated for HDF5 dataset");
            return -1;
        }
    }

    /* Everything's set up; do the writes */

    if (hdf5_ch_write_ph_flags(cfg_data, bsamp_data, nsamps) < 0) {
        goto fail;
    }

    if (hdf5_ch_write_sample_index(cfg_data, bsamp_data, nsamps) < 0) {

        goto fail;
    }

    if (hdf5_ch_write_chip_live(cfg_data, bsamp_data, nsamps) < 0) {
        goto fail;
    }

    if (hdf5_ch_write_channel_data(cfg_data, bsamp_data, nsamps) < 0) {
        goto fail;
    }

    if (hdf5_ch_write_aux_data(cfg_data, bsamp_data, nsamps) < 0) {
        goto fail;
    }


    cfg_data->h5_dset_off = next_offset;
    ret = 0; // success!
    fail:
        return ret;
}
