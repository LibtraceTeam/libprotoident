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

static inline bool match_mystery_99(lpi_data_t *data, lpi_module_t *mod UNUSED) {
	/* Another mystery protocol - this one is possibly something to do
         * with bittorrent, as I've seen it on port 6881 from time to time */

        /* Both payloads must match */
        if (data->payload[0] != data->payload[1])
                return false;

        /* One of the payloads is 99 bytes, the other is between 168 and 173
         * bytes */

        if (data->payload_len[0] == 99) {
                if (data->payload_len[1] >= 168 && data->payload_len[1] <= 173)
                        return true;
        }

        if (data->payload_len[1] == 99) {
                if (data->payload_len[0] >= 168 && data->payload_len[0] <= 173)
                        return true;
        }


	return false;
}

static lpi_module_t lpi_mystery_99 = {
	LPI_PROTO_UDP_MYSTERY_99,
	LPI_CATEGORY_NO_CATEGORY,
	"Mystery_99",
	250,
	match_mystery_99
};

void register_mystery_99(LPIModuleMap *mod_map) {
	register_protocol(&lpi_mystery_99, mod_map);
}

