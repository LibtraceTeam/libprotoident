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

static inline bool match_halflife(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!MATCHSTR(data->payload[0], "\xff\xff\xff\xff")) {
                if (data->payload_len[0] != 0)
                        return false;
        }
        if (!MATCHSTR(data->payload[1], "\xff\xff\xff\xff")) {
                if (data->payload_len[1] != 0)
                        return false;
        }

        if (data->payload_len[0] == 20 || data->payload_len[1] == 20)
                return true;
        if (data->payload_len[1] == 9 || data->payload_len[0] == 9)
                return true;
        if (data->payload_len[0] == 65 && (data->payload_len[1] > 500 &&
                        data->payload_len[1] < 600))
                return true;
        if (data->payload_len[1] == 65 && (data->payload_len[0] > 500 &&
                        data->payload_len[0] < 600))
                return true;
        if (data->payload_len[0] == 17 && data->payload_len[1] == 27)
                return true;
        if (data->payload_len[1] == 17 && data->payload_len[0] == 27)
                return true;


        /* This differs only slightly from Quake-based stuff, which replies
         * with 51-54 byte packets - hopefully this never overlaps, although
         * we could combine the two protocols if we have to into a generic
         * "Quake ancestry" protocol */
        if (data->payload_len[0] == 16) {
                if (data->payload_len[1] >= 45 && data->payload_len[1] <= 48)
                        return true;
        }
        if (data->payload_len[1] == 16) {
                if (data->payload_len[0] >= 45 && data->payload_len[0] <= 48)
                        return true;
        }

        /* Another combo observed on port 27005 */
        if (data->payload_len[0] == 87) {
                if (data->payload_len[1] >= 24 && data->payload_len[1] <= 26)
                        return true;
        }
        if (data->payload_len[1] == 87) {
                if (data->payload_len[0] >= 24 && data->payload_len[0] <= 26)
                        return true;
        }


        /*
        if (data->server_port != 27005 && data->client_port != 27005)
                return false;
        if (data->server_port != 27015 && data->client_port != 27015)
                return false;
        */


	return false;
}

static lpi_module_t lpi_halflife = {
	LPI_PROTO_UDP_HL,
	LPI_CATEGORY_GAMING,
	"HalfLife",
	3,
	match_halflife
};

void register_halflife(LPIModuleMap *mod_map) {
	register_protocol(&lpi_halflife, mod_map);
}

