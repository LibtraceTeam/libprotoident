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

static inline bool match_39_request(uint32_t payload, uint32_t len) {

	if (len != 4)
		return false;
	if (!MATCH(payload, 0x39, 0x18, 0x00, 0x00))
		return false;
	
	return true;

}

static inline bool match_3a_response(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;

	if (len != 8)
		return false;
	if (!MATCH(payload, 0x3a, 0x18, 0x00, 0x00))
		return false;
	
	return true;

}

static inline bool match_steam_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Master Server Queries begin with 31 ff 30 2e
         *
         * NOTE: the ff byte can vary depending on the region that the user
         * is querying for, but ff is the "all regions" option and is the
         * typical default. 
         */
        if (match_str_either(data, "\x31\xff\x30\x2e")
                        && match_str_either(data, "\xff\xff\xff\xff")) {
                return true;
        }

        /* Server Info queries are always 53 bytes and begin with ff ff ff ff.
         * The reply also begins with ff ff ff ff but can vary in size */

        if (MATCHSTR(data->payload[0], "\xff\xff\xff\xff") &&
                data->payload_len[0] == 25 &&
                (MATCHSTR(data->payload[1], "\xff\xff\xff\xff") ||
                data->payload_len[1] == 0)) {

                return true;
        }

        if (MATCHSTR(data->payload[1], "\xff\xff\xff\xff") &&
                data->payload_len[1] == 25 &&
                (MATCHSTR(data->payload[0], "\xff\xff\xff\xff") ||
                data->payload_len[0] == 0)) {

                return true;
        }

	/* This stuff is definitely related to Steam or some game played
	 * over Steam - need to look into this more at some point */

	if (match_39_request(data->payload[0], data->payload_len[0])) {
		if (match_3a_response(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_39_request(data->payload[1], data->payload_len[1])) {
		if (match_3a_response(data->payload[0], data->payload_len[0]))
			return true;
	}

	
	return false;
}

static lpi_module_t lpi_steam_udp = {
	LPI_PROTO_UDP_STEAM,
	LPI_CATEGORY_GAMING,
	"Steam_UDP",
	4,
	match_steam_udp
};

void register_steam_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_steam_udp, mod_map);
}

