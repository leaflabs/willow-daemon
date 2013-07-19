#include "sng.h"

#include "test.h"

#include <stdlib.h>

#include "type_attrs.h"
#include "proto/control.pb-c.h"

#define NSAMPLES 30000
START_TEST(test_libsng_store_samples)
{
    /* TODO: start the daemon at TEST_DAEMON_PATH if not already
     * running */
    int open_status = sng_open_connection("127.0.0.1", 1371);
    fail_unless(open_status == 0, "can't connect to daemon");

    ControlCmdStore store = CONTROL_CMD_STORE__INIT;
    store.path = "/tmp/foo.h5";
    store.has_nsamples = 1;
    store.nsamples = NSAMPLES;
    store.has_start_sample = 0;
    store.has_backend = 1;
    store.backend = STORAGE_BACKEND__STORE_HDF5;

    ControlResponse response;

    int store_status = sng_store_samples(&store, &response);
    fail_unless(store_status == 0, "can't perform sample storage command");
    ck_assert(response.has_type);
    ck_assert(response.type == CONTROL_RESPONSE__TYPE__STORE_FINISHED);
    ck_assert(response.store != NULL);
    ck_assert(!response.err);
    ck_assert(!response.reg_io);
    ck_assert(response.store->has_status);
    ck_assert_int_eq(response.store->status, CONTROL_RES_STORE__STATUS__DONE);
    ck_assert(response.store->has_nsamples);
    ck_assert_int_eq(response.store->nsamples, NSAMPLES);

    int close_status = sng_close_connection();
    fail_unless(close_status == 0, "can't close daemon connection");
}
END_TEST

Suite* libsng_suite(void)
{
    Suite *s = suite_create("libsng");
    TCase *tc_libsng = tcase_create("libsng");
    tcase_add_test(tc_libsng, test_libsng_store_samples);
    suite_add_tcase(s, tc_libsng);
    return s;
}

int main(__unused int argc, __unused char *argv[])
{
    Suite *s = libsng_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int n_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return n_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
