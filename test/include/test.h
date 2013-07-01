#ifndef _TEST_TEST_H_
#define _TEST_TEST_H_

#include <check.h>

/* For older versions of check that lack some ck_assert_int_XX(). */
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

#endif
