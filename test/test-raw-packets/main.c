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

/* Dummy packets. The copies are because sending mangles the originals. */
struct raw_pkt_cmd req1_pkt;
struct raw_pkt_cmd req1copy_pkt;
struct raw_pkt_cmd req2_pkt;
struct raw_pkt_cmd *req1 = &req1_pkt;
struct raw_pkt_cmd *req1copy = &req1copy_pkt;
struct raw_pkt_cmd *req2 = &req2_pkt;
struct raw_pkt_cmd err_pkt;
struct raw_pkt_cmd *err = &err_pkt;
const size_t bs_nsamp = 17;
struct raw_pkt_bsub *bsub1;
struct raw_pkt_bsub *bsub1copy;
struct raw_pkt_bsub *bsub2;
struct raw_pkt_bsmp bsmp1_pkt;
struct raw_pkt_bsmp bsmp1copy_pkt;
struct raw_pkt_bsmp bsmp2_pkt;
struct raw_pkt_bsmp *bsmp1 = &bsmp1_pkt;
struct raw_pkt_bsmp *bsmp1copy = &bsmp1copy_pkt;
struct raw_pkt_bsmp *bsmp2 = &bsmp2_pkt;

static void setup_raw(void)
{
    raw_packet_init(req1, RAW_MTYPE_REQ, 0);
    raw_packet_init(req1copy, RAW_MTYPE_REQ, 0);
    raw_packet_init(req2, RAW_MTYPE_REQ, 0);

    raw_packet_init(err, RAW_MTYPE_ERR, 0);

    raw_packet_init(bsmp1, RAW_MTYPE_BSMP, 0);
    raw_packet_init(bsmp1copy, RAW_MTYPE_BSMP, 0);
    raw_packet_init(bsmp2, RAW_MTYPE_BSMP, 0);

    bsub1 = raw_alloc_bsub(bs_nsamp);
    bsub1copy = raw_alloc_bsub(bs_nsamp);
    bsub2 = raw_alloc_bsub(bs_nsamp);

    if (bsub1 == 0 || bsub2 == 0 || bsub1copy == 0 ||
        socketpair(AF_UNIX, SOCK_DGRAM, 0, sockfd) != 0) {
        sockfd[0] = -1;
        sockfd[1] = -1;
        return;
    }

    memset(&req1->p, 0xAA, sizeof(struct raw_cmd_req));
    memset(&req2->p, 0x55, sizeof(struct raw_cmd_req));
    raw_pkt_copy(req1copy, req1);

    memset(&bsub1->b_samps, 0xAA, raw_bsub_sampsize(bsub1));
    memset(&bsub2->b_samps, 0x55, raw_bsub_sampsize(bsub2));
    raw_pkt_copy(bsub1copy, bsub1);

    memset(&bsmp1->b_samps, 0xAA, raw_bsmp_sampsize(bsmp1));
    memset(&bsmp2->b_samps, 0x55, raw_bsmp_sampsize(bsmp2));
    raw_pkt_copy(bsmp1copy, bsmp1);
}

static void teardown_raw(void)
{
    free(bsub1);
    free(bsub1copy);
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
    ck_assert_int_eq(raw_pkt_size(req1), sizeof(*req1));
    ck_assert_int_eq(raw_pkt_size(req1), sizeof(struct raw_pkt_cmd));
    ck_assert_int_eq(raw_pkt_size(err), sizeof(*err));
    if (bsub1) {
        const size_t bsub_size = (sizeof(struct raw_pkt_bsub) +
                                  bs_nsamp * sizeof(raw_samp_t));
        ck_assert_int_eq(raw_pkt_size(bsub1), bsub_size);
        ck_assert_int_eq(raw_bsub_size(bsub1), bsub_size);
    }
    ck_assert_int_eq(raw_pkt_size(bsmp1),
                     offsetof(struct raw_pkt_bsmp, b_samps) +
                     _RAW_BSMP_NSAMP * sizeof(raw_samp_t));
}
END_TEST

START_TEST(test_copy)
{
    ck_assert(bsub1 != 0);
    ck_assert(bsub2 != 0);

    ck_assert_int_eq(memcmp(req1copy, req1, raw_pkt_size(req1)), 0);
    ck_assert_int_eq(memcmp(bsub1copy, bsub1, raw_pkt_size(bsub1)), 0);
    ck_assert_int_eq(memcmp(bsmp1copy, bsmp1, raw_pkt_size(bsmp1)), 0);
}
END_TEST

#define do_roundtrip(dst, src, send_fn, recv_fn) do {           \
        size_t src_size = raw_pkt_size(src);                    \
        ssize_t send_status = send_fn(sockfd[0], src, 0);       \
        ck_assert_int_gt(send_status, 0);                       \
        ck_assert_int_eq((size_t)send_status, src_size);        \
        ssize_t recv_status = recv_fn(sockfd[1], dst, 0);       \
        ck_assert_int_gt(recv_status, 0);                       \
        ck_assert_int_eq((size_t)recv_status, src_size);        \
    } while (0)

#include <stdio.h>
START_TEST(test_roundtrips)
{
    /* Round-trip packets through the socket pair. */
    do_roundtrip(req2, req1,
                 raw_cmd_send,
                 raw_cmd_recv);
    ck_assert_int_eq(raw_bsub_nsamp(bsub1), raw_bsub_nsamp(bsub2));
    do_roundtrip(bsub2, bsub1,
                 raw_bsub_send,
                 raw_bsub_recv);
    do_roundtrip(bsmp2, bsmp1,
                 raw_bsmp_send,
                 raw_bsmp_recv);

    /* White box: check that multibyte fields are in network byte order. */
    size_t i;
    ck_assert_int_eq_h(raw_r_id(req1), htons(raw_r_id(req1copy)));
    ck_assert_int_eq_h(raw_r_val(req1), htonl(raw_r_val(req1copy)));
    ck_assert_int_eq_h(bsub1->b_cookie_h, htonl(bsub1copy->b_cookie_h));
    ck_assert_int_eq_h(bsub1->b_cookie_l, htonl(bsub1copy->b_cookie_l));
    ck_assert_int_eq_h(bsub1->b_id, htonl(bsub1copy->b_id));
    ck_assert_int_eq_h(bsub1->b_sidx, htonl(bsub1copy->b_sidx));
    ck_assert_int_eq_h(bsub1->b_nsamp, htonl(bsub1copy->b_nsamp));
    for (i = 0; i < raw_bsub_nsamp(bsub1copy); i++) {
        ck_assert_int_eq_h(bsub1->b_samps[i], htons(bsub1copy->b_samps[i]));
    }
    ck_assert_int_eq_h(bsmp1->b_cookie_h, htonl(bsmp1copy->b_cookie_h));
    ck_assert_int_eq_h(bsmp1->b_cookie_l, htonl(bsmp1copy->b_cookie_l));
    ck_assert_int_eq_h(bsmp1->b_id, htonl(bsmp1copy->b_id));
    ck_assert_int_eq_h(bsmp1->b_sidx, htonl(bsmp1copy->b_sidx));
    for (i = 0; i < raw_bsmp_nsamp(bsmp1copy); i++) {
        ck_assert_int_eq_h(bsmp1->b_samps[i], htons(bsmp1copy->b_samps[i]));
    }

    /* Make sure the packets round-tripped correctly. */
    ck_assert_int_eq(memcmp(&req2->ph, &req1copy->ph,
                            sizeof(struct raw_pkt_header)),
                     0);
    ck_assert_int_eq(memcmp(&bsub2->ph, &bsub1copy->ph,
                            sizeof(struct raw_pkt_header)),
                     0);
    ck_assert_int_eq(memcmp(&bsmp2->ph, &bsmp1copy->ph,
                            sizeof(struct raw_pkt_header)),
                     0);
    struct raw_cmd_req *cmd2 = raw_req(req2), *cmd1copy = raw_req(req1copy);
    ck_assert_int_eq_h(cmd2->r_id, cmd1copy->r_id);
    ck_assert_int_eq_h(cmd2->r_type, cmd1copy->r_type);
    ck_assert_int_eq_h(cmd2->r_addr, cmd1copy->r_addr);
    ck_assert_int_eq_h(cmd2->r_val, cmd1copy->r_val);
    ck_assert_int_eq_h(bsub2->b_cookie_h, bsub1copy->b_cookie_h);
    ck_assert_int_eq_h(bsub2->b_cookie_l, bsub1copy->b_cookie_l);
    ck_assert_int_eq_h(bsub2->b_id, bsub1copy->b_id);
    ck_assert_int_eq_h(bsub2->b_sidx, bsub1copy->b_sidx);
    ck_assert_int_eq_h(bsub2->b_nsamp, bsub1copy->b_nsamp);
    for (i = 0; i < raw_bsub_nsamp(bsub1copy); i++) {
        ck_assert_int_eq_h(bsub2->b_samps[i], bsub1copy->b_samps[i]);
    }
    ck_assert_int_eq_h(bsmp2->b_cookie_h, bsmp1copy->b_cookie_h);
    ck_assert_int_eq_h(bsmp2->b_cookie_l, bsmp1copy->b_cookie_l);
    ck_assert_int_eq_h(bsmp2->b_id, bsmp1copy->b_id);
    ck_assert_int_eq_h(bsmp2->b_sidx, bsmp1copy->b_sidx);
    for (i = 0; i< raw_bsmp_nsamp(bsmp1copy); i++) {
        ck_assert_int_eq_h(bsmp2->b_samps[i], bsmp1copy->b_samps[i]);
    }
    /* These memcmp()s are redundant if the above is up to date, but
     * they're future-proofing against additional fields being added */
    ck_assert_int_eq(memcmp(req2, req1copy, raw_pkt_size(req1copy)), 0);
    ck_assert_int_eq(memcmp(bsub2, bsub1copy, raw_pkt_size(bsub1copy)), 0);
    ck_assert_int_eq(memcmp(bsmp2, bsmp1copy, raw_pkt_size(bsmp1copy)), 0);
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
