#include "raw_packets.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <check.h>

/* For older versions of check that lack some ck_assert_int_XX().
 * TODO: move these to a header shared by all tests
 */
#ifndef ck_assert_int_lt
#define ck_assert_int_lt(X, Y) _ck_assert_int((X), <, (Y))
#endif
#ifndef ck_assert_int_le
#define ck_assert_int_le(X, Y) _ck_assert_int((X), <=, (Y))
#endif
#ifndef ck_assert_int_gt
#define ck_assert_int_gt(X, Y) _ck_assert_int((X), >, (Y))
#endif
#ifndef ck_assert_int_ge
#define ck_assert_int_ge(X, Y) _ck_assert_int((X), >=, (Y))
#endif

/* For convenience with values we want to see bits for
 * TODO move to shared test header
 * TODO send upstream patch */
#define _ck_assert_int_hex(X, O, Y)                                      \
    ck_assert_msg((X) O (Y),                                             \
                  "Assertion '"#X#O#Y"' failed: "#X"==0x%x, "#Y"==0x%x", \
                  X, Y)
#define ck_assert_int_eq_h(X, Y) _ck_assert_int_hex(X, ==, Y)
#define ck_assert_int_ne_h(X, Y) _ck_assert_int_hex(X, !=, Y)
#define ck_assert_int_lt_h(X, Y) _ck_assert_int_hex(X, <, Y)
#define ck_assert_int_le_h(X, Y) _ck_assert_int_hex(X, <=, Y)
#define ck_assert_int_gt_h(X, Y) _ck_assert_int_hex(X, >, Y)
#define ck_assert_int_ge_h(X, Y) _ck_assert_int_hex(X, >=, Y)

/* A socket pair to send and receive packets. */
int sockfd[2];

static void setup_raw(void)
{
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockfd) != 0) {
        sockfd[0] = -1;
        sockfd[1] = -1;
        return;
    }
}

static void teardown_raw(void)
{
    if (sockfd[0] != -1) {
        close(sockfd[0]);
    }
    if (sockfd[1] != -1) {
        close(sockfd[1]);
    }
}

START_TEST(test_sizes_packing)
{
    /* White box: make sure we get packed structure layout, or, while
     * round-trips will work, the FPGA will look things up in the
     * wrong places.
     *
     * Checking this here instead of forcing __packed is a performance
     * optimization -- we don't want to force the compiler to pack, or
     * dealing with raw data will generate slow code. */
    /* TODO */
}
END_TEST

START_TEST(test_create_bsamp)
{
    /* Basic sanity checks for raw_packet_create_bsamp(). */
    /* TODO */
}
END_TEST

START_TEST(test_roundtrips)
{
    /* Round-trip rsend into rrecv through socket pair. */
    /* TODO */

    /* White box: check rsend's multibyte fields got swapped properly. */
    /* TODO */

    /* Make sure the packet came back correctly by checking against
     * rsend_copy.  Use hex macros here; any errors are probably from
     * byte order. */
    /* TODO */
}
END_TEST

Suite* raw_packet_suite(void)
{
    Suite *s = suite_create("raw_packet");
    TCase *tc = tcase_create("raw_packet");
    tcase_add_checked_fixture(tc, setup_raw, teardown_raw);
    tcase_add_test(tc, test_sizes_packing);
    tcase_add_test(tc, test_create_bsamp);
    tcase_add_test(tc, test_roundtrips);
    suite_add_tcase(s, tc);
    return s;
}

int main(__unused int argc, __unused char *argv[])
{
    Suite *s = raw_packet_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int n_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return n_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
