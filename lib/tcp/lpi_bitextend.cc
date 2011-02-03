/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011 The University of Waikato, Hamilton, New Zealand.
 * Author: Shane Alcock
 *
 * With contributions from:
 *      Aaron Murrihy
 *      Donald Neal
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libprotoident; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* Bittorrent extensions (?)
 *
 * TODO Find some good references for this
 */

static inline bool match_bitextend(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_str_both(data, "\x0\x0\x0\xd", "\x0\x0\x0\x1"))
                return true;
        if (match_str_both(data, "\x0\x0\x0\x3", "\x0\x0\x0\x38"))
                return true;
        if (match_str_both(data, "\x0\x0\x0\x3", "\x0\x0\x0\x39"))
                return true;
        if (match_str_both(data, "\x0\x0\x0\x3", "\x0\x0\x0\x3"))
                return true;

        if (match_str_both(data, "\x0\x0\x0\x4e", "\x0\x0\x0\xb2"))
                return true;
        if (match_chars_either(data, 0x00, 0x00, 0x40, 0x09))
                return true;

        if (MATCH(data->payload[0], 0x00, 0x00, 0x01, ANY) &&
                MATCH(data->payload[1], 0x00, 0x00, 0x00, 0x38))
                return true;
        if (MATCH(data->payload[1], 0x00, 0x00, 0x01, ANY) &&
                MATCH(data->payload[0], 0x00, 0x00, 0x00, 0x38))
                return true;

        if (MATCH(data->payload[0], 0x00, 0x00, 0x00, ANY) &&
                MATCH(data->payload[1], 0x00, 0x00, 0x00, 0x05))
                return true;
        if (MATCH(data->payload[1], 0x00, 0x00, 0x00, ANY) &&
                MATCH(data->payload[0], 0x00, 0x00, 0x00, 0x05))
                return true;

        if (MATCH(data->payload[0], 0x01, 0x00, ANY, 0x68) &&
                MATCH(data->payload[1], 0x00, 0x00, 0x00, 0x05))
                return true;
        if (MATCH(data->payload[1], 0x01, 0x00, ANY, 0x68) &&
                MATCH(data->payload[0], 0x00, 0x00, 0x00, 0x05))
                return true;
	

	return false;
}

static lpi_module_t lpi_bitextend = {
	LPI_PROTO_BITEXT,
	LPI_CATEGORY_P2P,
	"Bittorrent_Extension",
	3, /* This is probably fine, but I'd rather have this at 3 than 2 */
	match_bitextend
};

void register_bitextend(LPIModuleMap *mod_map) {
	register_protocol(&lpi_bitextend, mod_map);
}

