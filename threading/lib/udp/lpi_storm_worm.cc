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

static inline bool match_storm_worm(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* This pattern is observed on ports 4000, 7871 and 11271 which are
         * all known port numbers for this trojan */

        if (MATCH(data->payload[0], 0xe3, 0x1b, 0xd6, 0x21)) {
                if (data->payload_len[0] != 4)
                        return false;
                if (data->payload_len[1] == 0)
                        return true;
                if (MATCH(data->payload[1], 0xe3, 0x0c, 0x66, 0xe6))
                        return true;
        }

        if (MATCH(data->payload[1], 0xe3, 0x1b, 0xd6, 0x21)) {
                if (data->payload_len[1] != 4)
                        return false;
                if (data->payload_len[0] == 0)
                        return true;
                if (MATCH(data->payload[0], 0xe3, 0x0c, 0x66, 0xe6))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_storm_worm = {
	LPI_PROTO_UDP_STORM_WORM,
	LPI_CATEGORY_MALWARE,
	"StormWorm",
	10,
	match_storm_worm
};

void register_storm_worm(LPIModuleMap *mod_map) {
	register_protocol(&lpi_storm_worm, mod_map);
}

