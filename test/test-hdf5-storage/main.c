#include <stdlib.h>

#include <hdf5.h>

#include "test.h"

#include "ch_storage.h"
#include "hdf5_ch_storage.h"
#include "logging.h"
#include "raw_packets.h"
#include "type_attrs.h"

#define H5FILE "test.hdf5"
#define H5DNAME "dummy-dataset"

#define COOKIE_H 0xdeadbeef
#define COOKIE_L 0xcafebea7
#define BOARD_ID 0x1eaf1ab5
#define CHIP_LIVE 0xffff5555

static struct raw_pkt_bsmp bsmp = {
    .ph = RAW_PKT_HEADER_INITIALIZER(RAW_MTYPE_BSMP),
    .b_cookie_h = COOKIE_H,
    .b_cookie_l = COOKIE_L,
    .b_id = BOARD_ID,
    .b_sidx = 0,
    .b_chip_live = CHIP_LIVE,
    .b_samps = { [RAW_BSMP_NSAMP - 1] = 0 },
};

/* Create, open, and write to a file. Close it, reopen it using the
 * HDF5 library directly, and make sure we get back what we
 * expected. */
START_TEST(test_hdf5_end_to_end)
{
    struct ch_storage *chns = hdf5_ch_storage_alloc(H5FILE, H5DNAME);

    for (size_t i = 0; i < RAW_BSMP_NSAMP; i++) {
        bsmp.b_samps[i] = i;
    }

    ck_assert(chns != NULL);
    ck_assert(ch_storage_open(chns, H5F_ACC_TRUNC) == 0);
    ck_assert(ch_storage_write(chns, &bsmp, 1) == 0);
    bsmp.b_sidx++;
    ck_assert(ch_storage_write(chns, &bsmp, 1) == 0);
    bsmp.b_sidx++;
    ck_assert(ch_storage_write(chns, &bsmp, 1) == 0);
    bsmp.b_sidx++;
    ck_assert(ch_storage_write(chns, &bsmp, 1) == 0);
    bsmp.b_sidx++;
    ck_assert(ch_storage_write(chns, &bsmp, 1) == 0);
    ck_assert(ch_storage_close(chns) == 0);
}
END_TEST

Suite* hdf5_suite(void)
{
    Suite *s = suite_create("hdf5");
    TCase *tc_hdf5 = tcase_create("hdf5");
    tcase_add_test(tc_hdf5, test_hdf5_end_to_end);
    suite_add_tcase(s, tc_hdf5);
    return s;
}

int main(__unused int argc, __unused char *argv[])
{
    logging_init(argv[0], LOG_DEBUG, 1);
    Suite *s = hdf5_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int n_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return n_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
