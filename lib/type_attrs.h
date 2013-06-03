/* Copyright (c) 2013 LeafLabs, LLC.
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file   type_attrs.h
 * @brief  Compiler-dependent type attributes
 *
 * These let us pretend that we might build with something other than
 * GCC someday.
 */

#ifndef _LIB_TYPE_ATTRS_H_
#define _LIB_TYPE_ATTRS_H_

#ifdef __GNUC__
#define __packed __attribute__((packed))
#define __unused __attribute__((unused))
#endif

#endif  /* _TYPE_ATTRS_H_ */
