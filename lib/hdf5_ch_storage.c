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
#define CHUNK_DIM0 50
#define CHUNK_DIM1 1
#define IS_LITTLE_ENDIAN (1 == *(unsigned char *)&(const int){1})
#define HOST_H5_ORDER (IS_LITTLE_ENDIAN ? H5T_ORDER_LE : H5T_ORDER_BE)
#define COOKIE_H5_TYPE H5T_NATIVE_UINT64
#define CHUNK_DIM  150000 // Set to largest expected standard write size which
                          // is currently sample.c, which uses nsamps=150000

static int hdf5_ch_open(struct ch_storage *chns, unsigned flags);
static int hdf5_ch_close(struct ch_storage *chns);
static int hdf5_ch_datasync(struct ch_storage *chns);
static int hdf5_ch_write(struct ch_storage *chns,
                         const struct raw_pkt_bsmp*,
                         size_t);
static void hdf5_ch_free(struct ch_storage *chns);

static const struct ch_storage_ops hdf5_ch_storage_ops = {
    .ch_open = hdf5_ch_open,
    .ch_close = hdf5_ch_close,
    .ch_datasync = hdf5_ch_datasync,
    .ch_write = hdf5_ch_write,
    .ch_free = hdf5_ch_free,
};

#define SIZE_TO_H5_UTYPE(x)                             \
    ({                                                  \
        hid_t __h5_utype = -1;                          \
        if (x == 1) {                                   \
            __h5_utype = H5T_NATIVE_UINT8;              \
        } else if (x == 2) {                            \
            __h5_utype = H5T_NATIVE_UINT16;             \
        } else if (x == 4) {                            \
            __h5_utype = H5T_NATIVE_UINT32;             \
        } else if (x == 8) {                            \
            __h5_utype = H5T_NATIVE_UINT64;             \
        } else {                                        \
            assert(0);                                  \
        }                                               \
        __h5_utype;                                     \
    })

/* Convert an unsigned integer (or unsigned type) to the corresponding
 * HDF5 type ID. */
#define TO_H5_UTYPE(x)                                  \
    ({                                                  \
        hid_t __h5_utype = SIZE_TO_H5_UTYPE(sizeof(x)); \
        __h5_utype;                                     \
    })

/* Dataset attributes and their names -- the numbers index into
 * h5_ch_data->h5_attrs, and aren't necessarily the same as their
 * indices in an HDF5 file. */
#define H5_ATTR_MTYPE     0  /* mtype (==RAW_MTYPE_BSMP) */
#define H5_ATTR_BOARD_ID  1  /* board identifier */
#define H5_ATTR_PVERS     2  /* protocol version */
#define H5_ATTR_COOKIE    3  /* experiment cookie */
#define H5_ATTR_PH_FLAGS  4  /* packet header flags */
#define H5_ATTR_MAX       5

struct exp_attr_info {
  size_t size;
  const char *name;
};

/* Can't store predefined HDF5 hid_t datatypes like H5T_NATIVE_UINT8 at
 * compile-time because these are actually function calls. Instead,
 * we only store the raw size of the attribute. */
#define FIELD_SZ(type, field)  (sizeof(((type *)NULL)->field))
static const struct exp_attr_info exp_attr_info[] = {
  [H5_ATTR_MTYPE]    = { FIELD_SZ(struct raw_pkt_header, p_mtype),      "raw_mtype" },
  [H5_ATTR_BOARD_ID] = { FIELD_SZ(struct raw_pkt_bsmp, b_id),           "board_id" },
  [H5_ATTR_PVERS]    = { FIELD_SZ(struct raw_pkt_header, p_proto_vers), "raw_proto_vers" },
  [H5_ATTR_COOKIE]   = { 8,                                             "experiment_cookie" },
  [H5_ATTR_PH_FLAGS] = { FIELD_SZ(struct raw_pkt_header, p_flags),      "ph_flags" }
};

#define H5_NATTRS (H5_ATTR_MAX)

#define H5_DSET_SAMPLE_INDEX  0
#define H5_DSET_CHANNEL_DATA  1
#define H5_DSET_AUX_DATA      2
#define H5_DSET_MAX           3

struct dset_info {
    size_t size;               // Size of each element in raw_pkt_bsmp
    size_t offset;             // offset of element in raw_pkt_bsmp
    size_t nelems;             // number of elements per raw_pkt_bsmp
    hsize_t rank;              // Dimensional rank of the dataset, must be either 1 or 2
    const char *name;
};

struct dset {
    hid_t dset;
    hid_t dspace;
    void *buf;                 // Buffer to hold contiguous elements
};

static const struct dset_info dset_info[] = {
    [H5_DSET_SAMPLE_INDEX] = {
        .size = FIELD_SZ(struct raw_pkt_bsmp, b_sidx),
        .offset = offsetof(struct raw_pkt_bsmp, b_sidx),
        .nelems = 1,
        .name = "sample_index",
        .rank = 1
    },
    [H5_DSET_CHANNEL_DATA] = {
        .size = sizeof(raw_samp_t),
        .offset = offsetof(struct raw_pkt_bsmp, b_samps),
        .nelems = 1024, // XXX
        .name = "channel_data",
        .rank = 2,
    },
    [H5_DSET_AUX_DATA] = {
        .size = sizeof(uint16_t),
        .offset = offsetof(struct raw_pkt_bsmp, b_samps) + (1024 * sizeof(raw_samp_t)),
        .nelems = 96, // XXX
        .name = "aux_data",
        .rank = 2,
    },
};

struct h5_ch_data {
    const char *dset_name;      /* dataset name */
    hid_t h5_file;              /* HDF5 file type */
    hid_t h5_dspace;            /* data space */
    hid_t h5_arrtype;           /* sample array (within bsamp) data type */
    hid_t h5_dtype;             /* board sample data type */
    hid_t h5_dset;              /* data set */
    hsize_t h5_chunk_dims[2];   /* data set chunk dimensions */
    hsize_t h5_dset_off;        /* current dataset write offset */
    hsize_t h5_dset_size;       /* current dataset size */
    struct dset dsets[H5_DSET_MAX];

    hid_t h5_attr_dspace;       /* attribute data space */
    hid_t h5_attrs[H5_NATTRS];  /* dataset-wide attributes (see H5_ATTR_*) */

    /* Some attributes can't be set until we get the first board
     * sample (e.g. experiment cookie). This field indicates whether
     * those fields have been set yet. */
    int h5_need_attrs;

    uint32_t h5_debug_board_id;
};

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
    /* TODO tune the chunk dimensions and the chunk cache */
    data->h5_chunk_dims[0] = CHUNK_DIM0;
    data->h5_chunk_dims[1] = CHUNK_DIM1;

    for (size_t i = 0; i < H5_DSET_MAX; i++) {
        data->dsets[i].dset = -1;
        data->dsets[i].dspace = -1;
        data->dsets[i].buf = NULL;
    }

    data->h5_dset_off = 0;
    data->h5_dset_size = 0;
    data->h5_attr_dspace = -1;
    for (size_t i = 0; i < H5_NATTRS; i++) {
        data->h5_attrs[i] = -1;
    }
    data->h5_need_attrs = 1;
    data->h5_debug_board_id = 0;
}

static int h5_ch_data_teardown(struct h5_ch_data *data)
{
    int ret = 0;

    for (size_t i = 0; i < H5_NATTRS; i++) {
        if (data->h5_attrs[i] != -1 && H5Aclose(data->h5_attrs[i])) {
            ret = -1;
        }
    }
    if (data->h5_attr_dspace >= 0 && H5Sclose(data->h5_attr_dspace) < 0) {
        ret = -1;
    }
    if (data->h5_dset >= 0 && H5Dclose(data->h5_dset) < 0) {
        ret = -1;
    }
    if (data->h5_arrtype >= 0 && H5Tclose(data->h5_arrtype) < 0) {
        ret = -1;
    }
    if (data->h5_dtype >= 0 && H5Tclose(data->h5_dtype) < 0) {
        ret = -1;
    }
    if (data->h5_dspace >= 0 && H5Sclose(data->h5_dspace) < 0) {
        ret = -1;
    }

    for (size_t i = 0; i < H5_DSET_MAX; i++) {
        struct dset *dset = &data->dsets[i];
        const struct dset_info *dsinfo = &dset_info[i];
        /* Truncate dataset on close */
        hsize_t size[] = { data->h5_dset_off, dsinfo->nelems };
        if (H5Dset_extent(dset->dset, size) < 0) {
            ret = -1;
        }
        if (H5Dclose(dset->dset) < 0) {
            ret = -1;
        }
        if (H5Sclose(dset->dspace) < 0) {
            ret = -1;
        }

        free(data->dsets[i].buf);
        data->dsets[i].buf = NULL;
    }

    if (data->h5_file >= 0 && H5Fclose(data->h5_file) < 0) {
        ret = -1;
    }

    return ret;
}

static int hdf5_write_close(hid_t *attr, hid_t mem_type_id, const void *buf)
{
    if (H5Awrite(*attr, mem_type_id, buf) < 0 || H5Aclose(*attr) < 0) {
        return -1;
    }
    *attr = -1;
    return 0;
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

/* Make the data space for storing board samples */
static hid_t hdf5_create_dspace(struct h5_ch_data *data)
{
    const hsize_t cur_dim = 0, max_dim = H5S_UNLIMITED;
    data->h5_dspace = H5Screate_simple(RANK, &cur_dim, &max_dim);
    return data->h5_dspace;
}

/* Make the data types for storing board samples */
static hid_t hdf5_create_dtypes(struct h5_ch_data *data)
{
    struct raw_pkt_bsmp bs;     /* just for type conversion/sizeof */
    hsize_t nsamps = RAW_BSMP_NSAMP;
    data->h5_arrtype = H5Tarray_create2(TO_H5_UTYPE(bs.b_samps[0]), 1,
                                        &nsamps);
    if (data->h5_arrtype < 0) {
        return -1;
    }
    data->h5_dtype = H5Tcreate(H5T_COMPOUND, sizeof(struct raw_pkt_bsmp));
    hid_t dtype = data->h5_dtype;
    if (data->h5_dtype < 0 ||
        H5Tinsert(dtype, "ph_flags", offsetof(struct raw_pkt_header, p_flags),
                  TO_H5_UTYPE(bs.ph.p_flags)) < 0 ||
        H5Tinsert(dtype, "samp_index", offsetof(struct raw_pkt_bsmp, b_sidx),
                  TO_H5_UTYPE(bs.b_sidx)) < 0 ||
        H5Tinsert(dtype, "chip_live",
                  offsetof(struct raw_pkt_bsmp, b_chip_live),
                  TO_H5_UTYPE(bs.b_chip_live)) < 0 ||
        H5Tinsert(dtype, "samples", offsetof(struct raw_pkt_bsmp, b_samps),
                  data->h5_arrtype) < 0) {
        return -1;
    }
    return data->h5_dtype;
}

/* Make the data set itself */
static hid_t hdf5_create_dset(struct h5_ch_data *data)
{
    hid_t ret = -1;
    hid_t cprops = H5Pcreate(H5P_DATASET_CREATE);
    if (cprops < 0) {
        return -1;
    }
    if (H5Pset_chunk(cprops, RANK, data->h5_chunk_dims) >= 0) {
        ret = H5Dcreate2(data->h5_file, data->dset_name,
                         data->h5_dtype, data->h5_dspace,
                         H5P_DEFAULT, cprops, H5P_DEFAULT);
    }
    H5Pclose(cprops);
    if (ret >= 0) {
        data->h5_dset = ret;
    }
    return ret;
}

static int hdf5_create_dsets(struct h5_ch_data *data) {
    int rc = -1;

    /* Create the sample_index dataset */
    for (size_t i = 0; i < H5_DSET_MAX; i++) {
        const struct dset_info *dsinfo = &dset_info[i];
        hsize_t rank = dsinfo->rank;

        /* Create dataset creation prop list and set the chunk size */
        const hsize_t chunk_dim[] = { CHUNK_DIM, dsinfo->nelems };
        hid_t cprops = H5Pcreate(H5P_DATASET_CREATE);
        H5Pset_chunk(cprops, rank, chunk_dim);

        const hsize_t cur_dim[]   = { 0, 0 };
        const hsize_t max_dim[]   = { H5S_UNLIMITED, dsinfo->nelems };
        hid_t dspace = H5Screate_simple(rank, cur_dim, max_dim);
        hid_t dset = H5Dcreate2(data->h5_file,
                                dsinfo->name,
                                SIZE_TO_H5_UTYPE(dsinfo->size),
                                dspace,
                                H5P_DEFAULT,
                                cprops,
                                H5P_DEFAULT);
        if (dset < 0) {
            log_ERR("Failed to create dataset: %s", dsinfo->name);
            H5Pclose(cprops);
            H5Dclose(dset);
            H5Sclose(dspace);
            goto done;
        };
        H5Pclose(cprops);

        void *buf = malloc(CHUNK_DIM * dsinfo->size * dsinfo->nelems);
        if (!buf) {
            H5Dclose(dset);
            H5Sclose(dspace);
            goto done;
        };

        data->dsets[i].dset = dset;
        data->dsets[i].dspace = dspace;
        data->dsets[i].buf = buf;
    };

    rc = 0;
done:
    return rc;
}

struct scatter_op_data {
    const struct raw_pkt_bsmp *bsamps;
    size_t scattered;                   // number of elements scattered, out of nsamps
    const struct dset_info *dsinfo;
};

/**
 * @brief Scatter callback. Progressively fill up src_buf with board sample
 * data until we've filled up nsamps of data. Will get called repeatedly until
 * buffer is filled.
 *
 * This fills an intermediate buffer allocated for each dataset so that we can
 * do a single contiguous hyperslab write.
 * @param src_buf (out) buffer to fill
 * @param src_buf_bytes_used (out) number of bytes filled
 * @param op_data (in) callback context
 */
static herr_t hdf5_scatter(const void **src_buf,
                           size_t *src_buf_bytes_used,
                           void *op_data) {
    struct scatter_op_data *args = (struct scatter_op_data*)op_data;
    const struct dset_info *dsinfo = args->dsinfo;

    /* First time through */
    if (*src_buf_bytes_used == 0) {
        args->scattered = 0;
    }

    size_t count = dsinfo->size * dsinfo->nelems;
    *src_buf = ((unsigned char*)&args->bsamps[args->scattered++] + dsinfo->offset);
    *src_buf_bytes_used = count;

    return 0;
};

static int hdf5_write_dsets(struct h5_ch_data* data,
                       const struct raw_pkt_bsmp *bsamps,
                       size_t nsamps) {
    int rc = -1;
    hid_t filespace = -1;

    for (size_t i = 0; i < H5_DSET_MAX; i++) {
        const struct dset_info *dsinfo = &dset_info[i];
        struct dset *dset = &data->dsets[i];
        hsize_t count[] = { nsamps, dsinfo->nelems };

        hid_t memspace = H5Screate_simple(dsinfo->rank, count, NULL);
        if (memspace < 0) {
            goto fail;
        }

        filespace = H5Dget_space(dset->dset);

        /* Create a count-sized selection */
        hsize_t offset[] = { data->h5_dset_off, 0 };
        rc = H5Sselect_hyperslab(filespace, H5S_SELECT_SET, offset,
                                 NULL, count, NULL);
        if (rc < 0) {
            log_ERR("failed to create hyperslab. count: %llu", count[0]);
            H5Sclose(memspace);
            goto fail;
        }

        /* Scatter bsamp data into the selection  */
        struct scatter_op_data args;
        args.bsamps = bsamps;
        args.dsinfo = dsinfo;

        H5Dscatter(hdf5_scatter, &args, SIZE_TO_H5_UTYPE(dsinfo->size),
                   memspace, dset->buf);

        rc = H5Dwrite(dset->dset, SIZE_TO_H5_UTYPE(dsinfo->size),
                      memspace, filespace, H5P_DEFAULT,
                      dset->buf);
        if (rc < 0) {
            log_ERR("failed to write h5dwriteee");
        }

        H5Sclose(memspace);
    }

    rc = 0; // success!
fail:
    if (rc) {
        log_ERR("Failed to write datasets");
    }
    return rc;
}

/* Add attributes for experiment-wide packet fields */
static hid_t hdf5_create_attrs(struct h5_ch_data *data)
{
    struct raw_pkt_bsmp bs;
    int rc = -1;
    raw_packet_init(&bs, RAW_MTYPE_BSMP, 0);

    /* The root group is the primary data object for these attributes. */
    hid_t root_group = H5Gopen2(data->h5_file, "/", H5P_DEFAULT);
    if (root_group < 0) {
        log_ERR("Failed to find root group");
        return -1;
    }

    /* The attributes all live in the same 1x1 dataspace. */
    const hsize_t curd = 1, maxd = 1;
    data->h5_attr_dspace = H5Screate_simple(1, &curd, &maxd);
    if (data->h5_attr_dspace < 0) {
        goto cleanup;
    }

    /* Create the attributes. */
    for (size_t i = 0; i < H5_NATTRS; i++) {
      data->h5_attrs[i] = H5Acreate2(root_group,
                                     exp_attr_info[i].name,
                                     SIZE_TO_H5_UTYPE(exp_attr_info[i].size),
                                     data->h5_attr_dspace,
                                     H5P_DEFAULT,
                                     H5P_DEFAULT);
    }

    for (size_t i = 0; i < H5_NATTRS; i++) {
        /* Note that this also checks if we missed one. */
        if (data->h5_attrs[i] < 0) {
            goto cleanup;
        }
    }

    /* Write and close any attributes with known values. */
    if (hdf5_write_close(data->h5_attrs + H5_ATTR_MTYPE,
                         TO_H5_UTYPE(bs.ph.p_mtype),
                         &bs.ph.p_mtype) < 0 ||
        hdf5_write_close(data->h5_attrs + H5_ATTR_PVERS,
                         TO_H5_UTYPE(bs.ph.p_proto_vers),
                         &bs.ph.p_proto_vers) < 0) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    H5Gclose(root_group);
    return rc;
}

static int hdf5_ch_open(struct ch_storage *chns, unsigned flags)
{
    struct h5_ch_data tmp;
    h5_ch_data_init(&tmp, h5_data(chns)->dset_name); /* initialize defaults */

    tmp.h5_file = H5Fcreate(chns->ch_path, flags, H5P_DEFAULT, H5P_DEFAULT);
    if (tmp.h5_file < 0) {
        goto fail;
    }
    if (hdf5_create_dspace(&tmp) < 0) {
        goto fail;
    }
    if (hdf5_create_dtypes(&tmp) < 0) {
        goto fail;
    }
    if (hdf5_create_dset(&tmp) < 0) {
        goto fail;
    }

    if (hdf5_create_dsets(&tmp) < 0) {
        goto fail;
    }

    if (hdf5_create_attrs(&tmp) < 0) {
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

static int hdf5_ch_close(struct ch_storage *chns)
{
    struct h5_ch_data *data = h5_data(chns);
    if (H5Dset_extent(data->h5_dset, &data->h5_dset_off) < 0) {
        log_ERR("Can't clean up dataset on close; sample data in "
                "%s, dataset %s after offset %llu will be garbage",
                chns->ch_path, data->dset_name,
                (long long unsigned)data->h5_dset_off);
    }
    return h5_ch_data_teardown(h5_data(chns));
}

static int hdf5_ch_datasync(struct ch_storage *chns)
{
    return H5Fflush(h5_data(chns)->h5_file, H5F_SCOPE_LOCAL);
}

/* Initialize dataset attributes that require a board sample to fill in. */
static void hdf5_init_exp_attrs(struct ch_storage *chns,
                                const struct raw_pkt_bsmp *bs)
{
    struct h5_ch_data *data = h5_data(chns);
    int rc;
    raw_cookie_t cookie = raw_exp_cookie(bs);
    if (hdf5_write_close(data->h5_attrs + H5_ATTR_BOARD_ID,
                         TO_H5_UTYPE(bs->b_id), &bs->b_id) ||
        hdf5_write_close(data->h5_attrs + H5_ATTR_COOKIE,
                         COOKIE_H5_TYPE, &cookie)) {
        log_ERR("Can't initialize some HDF5 attributes "
                "(board_id=%llu, cookie=%llu), "
                "some data will be missing",
                (long long unsigned)bs->b_id,
                (long long unsigned)raw_exp_cookie(bs));
    }

    uint8_t ph_flags = bs->ph.p_flags;
    rc = hdf5_write_close(&data->h5_attrs[H5_ATTR_PH_FLAGS],
                          TO_H5_UTYPE(ph_flags), &ph_flags);
    if (rc < 0) {
        log_ERR("Can't initialize some HDF5 attributes (ph_flags=%x)",
                (unsigned int)ph_flags);

    }
}

/* Increase the size of the dataset to make room for more samples. */
static herr_t hdf5_extend(struct h5_ch_data *data, hsize_t minsize)
{
    hsize_t newsize;
    if (data->h5_dset_size) {
        newsize = (double)data->h5_dset_size * DSET_EXTEND_FACTOR + 0.5;
    } else {
        newsize = 1;
    }
    if (newsize < minsize) {
        newsize = minsize;
    }
#if RANK != 1
#error "If RANK !=1, hdf5_extend is broken"
#endif
    herr_t ret = H5Dset_extent(data->h5_dset, &newsize);
    if (ret < 0) {
        return -1;
    };

    for (size_t i = 0; i < H5_DSET_MAX; i++) {
        const struct dset_info *dsinfo = &dset_info[i];
        hsize_t size[] = { newsize, dsinfo->nelems };
        ret = H5Dset_extent(data->dsets[i].dset, size);
        if (ret < 0) {
            return -1;
        };
    }

    data->h5_dset_size = newsize;
    return ret;
}

static int hdf5_ch_write(struct ch_storage *chns,
                         const struct raw_pkt_bsmp *bsamps,
                         size_t nsamps)
{
    struct h5_ch_data *data = h5_data(chns);
    if (!nsamps) {
        return 0;
    }

    /* Too large */
    if (nsamps > CHUNK_DIM) {
        return -1;
    };

    /* Take care of "first write" bookkeeping. */
    if (data->h5_need_attrs) {
        data->h5_debug_board_id = bsamps[0].b_id;
        hdf5_init_exp_attrs(chns, bsamps);
        data->h5_need_attrs = 0;
    }

    /* Sanity-check that we're not getting packets from a different board. */
    assert(bsamps[0].b_id == data->h5_debug_board_id);

    /* If we're getting more board samples than will fit, we need to
     * extend the dataset. */
    hsize_t next_offset = data->h5_dset_off + nsamps;
    if (next_offset >= data->h5_dset_size) {
        if (hdf5_extend(data, next_offset) < 0) {
            log_ERR("Can't increase space allocated for HDF5 dataset");
            return -1;
        }
    }

    /* Everything's set up; do the write. */
    int ret = -1;
    hsize_t slabdims[RANK] = {(hsize_t)nsamps};
    hid_t filespace = -1;
    hid_t memspace = -1;

    filespace = H5Dget_space(data->h5_dset);
    if (filespace < 0) {
        goto fail;
    }
    memspace = H5Screate_simple(RANK, slabdims, NULL);
    if (memspace < 0) {
        goto fail;
    }
    if (H5Sselect_hyperslab(filespace, H5S_SELECT_SET, &data->h5_dset_off,
                            NULL, slabdims, NULL) < 0) {
        goto fail;
    }
    if (H5Dwrite(data->h5_dset, data->h5_dtype, memspace, filespace,
                 H5P_DEFAULT, bsamps) < 0) {
        goto fail;
    }

    /* Write datasets */
    ret = hdf5_write_dsets(data, bsamps, nsamps);
    if (ret < 0) {
        goto fail;
    };

    data->h5_dset_off = next_offset;
    ret = 0;
 fail:
    if (filespace != -1 && H5Sclose(filespace) < 0) {
        log_ERR("can't free resources acquired while writing samples");
    }
    if (memspace != -1 && H5Sclose(memspace) < 0) {
        log_ERR("can't free resources acquired while writing samples");
    }
    return ret;
}
