/*
 *
 * Copyright (c) 2011-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libprotoident.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* Protocol is not documented and goes through all sorts of revisions
 * (mainly to stop hax0rs, no doubt) - so this is mostly based on 
 * observations of traffic to Jagex servers and messing around with the 
 * game myself
 */

static inline bool match_runescape_req(uint32_t payload, uint32_t len) {

	if (len == 1 || len == 105) {
               	if (MATCH(payload, 0x00, 0x00, 0x00, 0x00))
	        	return true;
        }
	return false;

}

static inline bool match_runescape_resp(uint32_t payload, uint32_t len) {

	/* Don't allow empty responses, as the request rule is rather 
	 * non-specific */

	/* First byte appears to be a packet type
	 * Second bytes is the packet length - 2
	 *
	 * It appears many types have a fixed size anyway, so no need to
	 * get fancy :)
	 */

	if (MATCH(payload, 0x0f, 0x29, 0x00, 0x00)) {
		if (len == 43)
			return true;
	}

	if (MATCH(payload, 0x0f, 0x2a, 0x00, 0x00)) {
		if (len == 44)
			return true;
	}

	if (MATCH(payload, 0x0e, 0x00, 0x00, 0x00)) {
		if (len == 1)
			return true;
	}
	if (MATCH(payload, 0x0f, 0x00, 0x00, 0x00)) {
		if (len == 1)
			return true;
	}
	return false;

}

static inline bool match_runescape(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_runescape_req(data->payload[0], data->payload_len[0])) {
		if (match_runescape_resp(data->payload[1], 
				data->payload_len[1])) {
			return true;
		}
	}
	if (match_runescape_req(data->payload[1], data->payload_len[1])) {
		if (match_runescape_resp(data->payload[0], 
				data->payload_len[0])) {
			return true;
		}
	}

	return false;
}

static lpi_module_t lpi_runescape = {
	LPI_PROTO_RUNESCAPE,
	LPI_CATEGORY_GAMING,
	"Runescape",
	9,
	match_runescape
};

void register_runescape(LPIModuleMap *mod_map) {
	register_protocol(&lpi_runescape, mod_map);
}

