/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

#include "chaos.h"
#include "config.h"
#include "logging.h"

#include <stdlib.h>
#include <time.h>

/* Chaos-related configuration variables */
const double config_chaos_p_bsamp_drop = 0.5;
const double config_chaos_p_bsamp_dup = 0.5;

/* Whether or not we should roll dice */
static int chaos_enabled_p = 0;

/* Nonportable; uses re-entrant GNU extensions to libc random number
 * interfaces */
/* FIXME use thread local storage instead of dr_buf when multithreaded */
static struct drand48_data dr_buf;
static int roll_dice(double p_win)
{
    if (!chaos_enabled_p) {
        return 0;
    }
    double die;
    drand48_r(&dr_buf, &die);
    return p_win > die;
}

void chaos_init(int enable_chaos)
{
    chaos_enabled_p = enable_chaos;
    long seed = (long)time(0);
    log_INFO("chaos seed: %ld", seed);
    srand48_r(seed, &dr_buf); /* FIXME use TLS instead of dr_buf. */
}

int chaos_bs_drop_p(void)
{
    return roll_dice(config_chaos_p_bsamp_drop);
}

int chaos_bs_dup_p(void)
{
    return roll_dice(config_chaos_p_bsamp_dup);
}
