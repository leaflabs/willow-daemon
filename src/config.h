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

#ifndef _SRC_CONFIG_H_
#define _SRC_CONFIG_H_

/* If 0, do not attempt to reset the SATA read FIFO when starting a
 * storage command.
 *
 * (Hack-around for using older sng-firmware versions that don't
 * support RAW_RADDR_SATA_R_FIFO_RST; should be removed once we've got
 * a working version that does support it.) */
#ifndef CONFIG_RESET_SATA_READ_FIFO
#define CONFIG_RESET_SATA_READ_FIFO 1
#endif

#endif
