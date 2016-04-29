/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011-2015 The University of Waikato, Hamilton, New Zealand.
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

static inline bool match_mystery_iG(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Another mystery protocol - the payload pattern is the same in
         * both directions. Have observed this on port 20005 and port 8080,
         * but not obvious what exactly this is */

        if (match_str_both(data, "\xd7\x69\x47\x26", "\xd7\x69\x47\x26"))
                return true;
        if (MATCH(data->payload[0], 0xd7, 0x69, 0x47, 0x26)) {
                if (data->payload_len[1] == 0)
                        return true;
        }
        if (MATCH(data->payload[1], 0xd7, 0x69, 0x47, 0x26)) {
                if (data->payload_len[0] == 0)
                        return true;
        }
	

	return false;
}

static lpi_module_t lpi_mystery_iG = {
	LPI_PROTO_MYSTERY_IG,
	LPI_CATEGORY_NO_CATEGORY,
	"Mystery_iG",
	250,
	match_mystery_iG
};

void register_mystery_iG(LPIModuleMap *mod_map) {
	register_protocol(&lpi_mystery_iG, mod_map);
}

