/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

/*
 * Convenience interface for whether or not we should cause chaos; see
 * config.h and the --chaos argument dealt with in main.c.
 */

#ifndef _TEST_DUMMY_DATANODE_CHAOS_H_
#define _TEST_DUMMY_DATANODE_CHAOS_H_

/* Call this once. */
void chaos_init(int enable_chaos);

/* Roll the dice and decide whether to drop a board sample packet. */
int chaos_bs_drop_p(void);

/* Roll the dice and decide whether to duplicate a board sample packet. */
int chaos_bs_dup_p(void);

#endif
