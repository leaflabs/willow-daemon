/* Copyright (c) 2013 LeafLabs, LLC. All rights reserved. */

/**
 * @file   type_attrs.h
 * @brief  Compiler-dependent type attributes
 *
 * These let us pretend that we might build with something other than
 * GCC someday.
 */

#ifndef _TYPE_ATTRS_H_
#define _TYPE_ATTRS_H_

#ifdef __GNUC__
#define __packed __attribute__((packed))
#define __unused __attribute__((unused))
#endif

#endif  /* _TYPE_ATTRS_H_ */
