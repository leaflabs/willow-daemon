/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

#ifndef _TEST_DUMMY_DATANODE_CONFIG_H_
#define _TEST_DUMMY_DATANODE_CONFIG_H_

/*
 * Chaos configuration. These are all probabilities (i.e., floating
 * point values between 0.0 and 1.0) of events or actions. Add more
 * and then respect them in the rest of the sources to test the
 * daemon's resilience.
 */

/* Probability a board sample packet is dropped. If the event occurs,
 * we don't even try to send the packet once. */
extern const double config_chaos_p_bsamp_drop;
/* Probability a board sample packet we try to send is
 * duplicated. This is the parameter to a Bernoulli process, so if we
 * try sending the packet at all, then
 *
 *   Pr(try sending exactly twice) = P = config_chaos_p_bsamp_dup,
 *
 * and
 *
 *   Pr(try sending exactly three times) = P^2,
 *
 * etc. */
extern const double config_chaos_p_bsamp_dup;
/* TODO: think about chaos for packet reordering, at least when
 * multiple board samples are asked for in a single request. */

#endif
