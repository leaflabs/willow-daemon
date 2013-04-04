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

/* Values to use for raw_packet.p.bsamp.bs_(nchips,nlines) */
#define BSAMP_FLAGS  (RAW_FLAG_BSAMP_IS_LIVE | RAW_FLAG_BSAMP_IS_LAST)
#define BSAMP_IDX    0xAA550011
#define BSAMP_NCHIPS 0x0002
#define BSAMP_NLINES 0x0100

/* A pair of initialized bsamp packets with above configuration */
struct raw_packet *rsend;
struct raw_packet *rsend_copy;  /* raw_packet_send() trashes its argument */
struct raw_packet *rrecv;

/* A socket pair to send and receive packets. */
int sockfd[2];

static void setup_raw(void)
{
    rsend = raw_packet_create_bsamp(BSAMP_NCHIPS, BSAMP_NLINES);
    rrecv = raw_packet_create_bsamp(BSAMP_NCHIPS, BSAMP_NLINES);
    rsend_copy = raw_packet_create_bsamp(BSAMP_NCHIPS, BSAMP_NLINES);

    if (rsend == 0 || rrecv == 0 || rsend_copy == 0 ||
        socketpair(AF_UNIX, SOCK_DGRAM, 0, sockfd) != 0) {
        /* For sanity in writing test cases, they'll all be there, or
         * none will. */
        rsend = rrecv = rsend_copy = 0;
        sockfd[0] = -1;
        sockfd[1] = -1;
        return;
    }

    rsend->p_flags = BSAMP_FLAGS;
    rsend->p.bsamp.bs_idx = BSAMP_IDX;
    for (size_t i = 0; i < raw_packet_nsamps(rsend); i++) {
        rsend->p.bsamp.bs_samples[i] = (raw_samp_t)i;
    }

    raw_packet_copy(rsend_copy, rsend);
}

static void teardown_raw(void)
{
    free(rsend);
    free(rsend_copy);
    free(rrecv);
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
    ck_assert_int_eq(sizeof(struct raw_msg_bsamp), 8);
    ck_assert_int_eq(offsetof(struct raw_msg_bsamp, bs_idx), 0);
    ck_assert_int_eq(offsetof(struct raw_msg_bsamp, bs_nchips), 4);
    ck_assert_int_eq(offsetof(struct raw_msg_bsamp, bs_nlines), 6);
    ck_assert_int_eq(offsetof(struct raw_msg_bsamp, bs_samples), 8);
    ck_assert_int_eq(sizeof(struct raw_msg_req), 8);
    ck_assert_int_eq(offsetof(struct raw_msg_req, r_id), 0);
    ck_assert_int_eq(offsetof(struct raw_msg_req, r_type), 2);
    ck_assert_int_eq(offsetof(struct raw_msg_req, r_addr), 3);
    ck_assert_int_eq(offsetof(struct raw_msg_req, r_val), 4);
    ck_assert_int_eq(sizeof(struct raw_msg_res), 8);
    ck_assert_int_eq(sizeof(struct raw_packet), 12);
    ck_assert_int_eq(offsetof(struct raw_packet, _p_magic), 0);
    ck_assert_int_eq(offsetof(struct raw_packet, _p_proto_vers), 1);
    ck_assert_int_eq(offsetof(struct raw_packet, p_type), 2);
    ck_assert_int_eq(offsetof(struct raw_packet, p_flags), 3);
}
END_TEST

START_TEST(test_create_bsamp)
{
    /* Basic sanity checks for raw_packet_create_bsamp(). */
    ck_assert(rsend != 0);
    ck_assert_int_eq(raw_packet_nsamps(rsend), BSAMP_NCHIPS * BSAMP_NLINES);
    ck_assert_int_eq(raw_packet_sampsize(rsend),
                     BSAMP_NCHIPS * BSAMP_NLINES * sizeof(raw_samp_t));
    ck_assert_int_eq(rsend->p_type, RAW_PKT_TYPE_BSAMP);
}
END_TEST

START_TEST(test_roundtrips)
{
    size_t i;

    ck_assert(rsend != 0 && rrecv != 0 && rsend_copy != 0);

    struct raw_msg_bsamp *smsg = &rsend->p.bsamp,
        *rmsg = &rrecv->p.bsamp,
        *scmsg = &rsend_copy->p.bsamp;

    /* Round-trip rsend into rrecv through socket pair. */
    ck_assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockfd) == 0);
    ssize_t send_status = raw_packet_send(sockfd[0], rsend, 0);
    ck_assert_int_gt(send_status, 0);
    ck_assert_int_eq(rrecv->p_type, RAW_PKT_TYPE_BSAMP);
    ssize_t recv_status = raw_packet_recv(sockfd[1], rrecv, 0);
    ck_assert_int_gt(recv_status, 0);

    /* White box: check rsend's multibyte fields got swapped properly. */
    ck_assert_int_eq_h(smsg->bs_idx, htonl(BSAMP_IDX));
    ck_assert_int_eq_h(smsg->bs_nchips, htons(BSAMP_NCHIPS));
    ck_assert_int_eq_h(smsg->bs_nlines, htons(BSAMP_NLINES));
    for (i = 0; i < raw_bsamp_nsamps(smsg); i++) {
        ck_assert_int_eq_h(smsg->bs_samples[i], htons(scmsg->bs_samples[i]));
    }

    /* Make sure the packet came back correctly by checking against
     * rsend_copy.  Use hex macros here; any errors are probably from
     * byte order. */
    ck_assert_int_eq_h(rsend_copy->_p_magic, rrecv->_p_magic);
    ck_assert_int_eq_h(rsend_copy->_p_proto_vers, rrecv->_p_proto_vers);
    ck_assert_int_eq_h(rsend_copy->p_type, rrecv->p_type);
    ck_assert_int_eq_h(RAW_PKT_TYPE_BSAMP, rsend_copy->p_type);
    ck_assert_int_eq_h(rsend_copy->p_flags, rrecv->p_flags);
    ck_assert_int_eq_h(raw_bsamp_nsamps(scmsg), raw_bsamp_nsamps(rmsg));
    ck_assert_int_eq_h(scmsg->bs_idx, rmsg->bs_idx);
    ck_assert_int_eq_h(scmsg->bs_nchips, rmsg->bs_nchips);
    ck_assert_int_eq_h(scmsg->bs_nlines, rmsg->bs_nlines);
    for (i = 0; i < raw_bsamp_nsamps(scmsg); i++) {
        ck_assert_int_eq_h(scmsg->bs_samples[i], rmsg->bs_samples[i]);
    }
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
