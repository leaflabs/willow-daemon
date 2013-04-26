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

/* Dummy packets */
struct raw_pkt_cmd req1;
struct raw_pkt_cmd req2;
struct raw_pkt_cmd err;
const size_t bs_nsamp = 213;
struct raw_pkt_bsub *bsub1;
struct raw_pkt_bsub *bsub2;
struct raw_pkt_bsmp bsmp1;
struct raw_pkt_bsmp bsmp2;

static void setup_raw(void)
{
    raw_packet_init(&req1, RAW_MTYPE_REQ, 0);
    raw_packet_init(&req2, RAW_MTYPE_REQ, 0);
    raw_packet_init(&err, RAW_MTYPE_ERR, 0);
    raw_packet_init(&bsmp1, RAW_MTYPE_BSMP, 0);
    raw_packet_init(&bsmp2, RAW_MTYPE_BSMP, 0);
    bsub1 = raw_alloc_bsub(bs_nsamp);
    bsub2 = raw_alloc_bsub(bs_nsamp);
    if (bsub1 == 0 || bsub2 == 0 ||
        socketpair(AF_UNIX, SOCK_DGRAM, 0, sockfd) != 0) {
        sockfd[0] = -1;
        sockfd[1] = -1;
        return;
    }
    memset(&req2.p, 0xFF, sizeof(struct raw_cmd_req));
    memset(&bsub1->b_samps, 0x00, raw_bsub_sampsize(bsub1));
    memset(bsub2, 0xFF, raw_pkt_size(bsub2));
    memset(&bsmp1.b_samps, 0x00, raw_bsmp_sampsize(&bsmp1));
    memset(&bsmp2, 0xFF, raw_pkt_size(&bsmp2));
}

static void teardown_raw(void)
{
    free(bsub1);
    free(bsub2);
    if (sockfd[0] != -1) {
        close(sockfd[0]);
    }
    if (sockfd[1] != -1) {
        close(sockfd[1]);
    }
}

START_TEST(test_sizes_packing)
{
    ck_assert(bsub1 != 0);

    /* Make sure all the command packet structs are the same size. */
    ck_assert_int_eq(sizeof(struct raw_cmd_req), sizeof(struct raw_cmd_res));
    ck_assert_int_eq(sizeof(struct raw_cmd_req), sizeof(struct raw_cmd_err));

    /* White box: make sure we get packed structure layout, or, while
     * round-trips will work, the FPGA will look things up in the
     * wrong places.
     *
     * Checking this here instead of forcing __packed is a performance
     * optimization -- we don't want to force the compiler to pack, or
     * dealing with raw data will generate slow code. */

    ck_assert_int_eq(offsetof(struct raw_pkt_header, _p_magic), 0);
    ck_assert_int_eq(offsetof(struct raw_pkt_header, p_proto_vers), 1);
    ck_assert_int_eq(offsetof(struct raw_pkt_header, p_mtype), 2);
    ck_assert_int_eq(offsetof(struct raw_pkt_header, p_flags), 3);

    ck_assert_int_eq(offsetof(struct raw_cmd_req, r_id), 0);
    ck_assert_int_eq(offsetof(struct raw_cmd_req, r_type), 2);
    ck_assert_int_eq(offsetof(struct raw_cmd_req, r_addr), 3);
    ck_assert_int_eq(offsetof(struct raw_cmd_req, r_val), 4);

    ck_assert_int_eq(offsetof(struct raw_pkt_bsub, b_cookie_h), 4);
    ck_assert_int_eq(offsetof(struct raw_pkt_bsub, b_cookie_l), 8);
    ck_assert_int_eq(offsetof(struct raw_pkt_bsub, b_id), 12);
    ck_assert_int_eq(offsetof(struct raw_pkt_bsub, b_sidx), 16);
    ck_assert_int_eq(offsetof(struct raw_pkt_bsub, b_nsamp), 20);
    ck_assert_int_eq(offsetof(struct raw_pkt_bsub, b_samps), 24);

    ck_assert_int_eq(offsetof(struct raw_pkt_bsmp, b_cookie_h), 4);
    ck_assert_int_eq(offsetof(struct raw_pkt_bsmp, b_cookie_l), 8);
    ck_assert_int_eq(offsetof(struct raw_pkt_bsmp, b_id), 12);
    ck_assert_int_eq(offsetof(struct raw_pkt_bsmp, b_sidx), 16);
    ck_assert_int_eq(offsetof(struct raw_pkt_bsub, b_nsamp), 20);
    ck_assert_int_eq(offsetof(struct raw_pkt_bsub, b_samps), 24);

    /* White box: packet headers are always at offset 0 (prevents
     * careless insertions, and some routines rely on it -- we should
     * be using container_of() instead, but oh well.) */

    ck_assert_int_eq(offsetof(struct raw_pkt_cmd, ph),0);
    ck_assert_int_eq(offsetof(struct raw_pkt_bsub, ph), 0);
    ck_assert_int_eq(offsetof(struct raw_pkt_bsmp, ph), 0);

    /* Check that packet sizing works as intended */

    ck_assert_int_eq(raw_pkt_size(&err), sizeof(err));
    if (bsub1) {
        const size_t bsub_size = (sizeof(struct raw_pkt_bsub) +
                                  bs_nsamp * sizeof(raw_samp_t));
        ck_assert_int_eq(raw_pkt_size(bsub1), bsub_size);
        ck_assert_int_eq(raw_bsub_size(bsub1), bsub_size);
    }
    ck_assert_int_eq(raw_pkt_size(&bsmp1),
                     offsetof(struct raw_pkt_bsmp, b_samps) +
                     _RAW_BSMP_NSAMP * sizeof(raw_samp_t));
}
END_TEST

START_TEST(test_copy)
{
    ck_assert(bsub1 != 0);
    ck_assert(bsub2 != 0);

    /* Copy requests */
    raw_pkt_copy(&req2, &req1);
    ck_assert_int_eq(memcmp(&req2, &req1, raw_pkt_size(&req1)), 0);

    /* Copy board subsamples */
    raw_pkt_copy(bsub2, bsub1);
    ck_assert_int_eq(memcmp(bsub2, bsub1, raw_bsub_size(bsub1)), 0);

    /* Copy board samples */
    raw_pkt_copy(&bsmp2, &bsmp1);
    ck_assert_int_eq(memcmp(&bsmp2, &bsmp1, raw_bsmp_size(&bsmp1)), 0);
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
    tcase_add_test(tc, test_copy);
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
