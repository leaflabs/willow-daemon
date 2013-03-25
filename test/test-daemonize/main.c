#include <unistd.h>
#include <stdlib.h>

#include <check.h>

#include "daemon.h"
#include "type_attrs.h"

START_TEST(test_daemonize)
{
    fail_unless(daemonize(0, 0) == 0, "Can't daemonize");
    pid_t ppid = getppid();
    fail_unless(ppid == 1,
                "Expected to be a child of init, but getppid()=%d", ppid);
}
END_TEST

Suite* daemon_suite(void)
{
    Suite *s = suite_create("daemon");
    TCase *tc_daemonize = tcase_create("daemonize");
    tcase_add_test(tc_daemonize, test_daemonize);
    suite_add_tcase(s, tc_daemonize);
    return s;
}

int main(__unused int argc, __unused char *argv[])
{
    Suite *s = daemon_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int n_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return n_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
