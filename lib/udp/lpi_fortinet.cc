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

static inline bool match_fortinet_req(uint32_t payload, uint32_t len) {

	if (MATCHSTR(payload, "ikro"))
		return true;
	if (MATCHSTR(payload, "ikuo"))
		return true;


        /* All the following strings require a 64 byte datagram */
        if (len != 64)
		return false;

	if (MATCHSTR(payload, "ihrk"))
		return true;
	if (MATCHSTR(payload, "ihri"))
		return true;
	if (MATCHSTR(payload, "iiri"))
		return true;
	if (MATCHSTR(payload, "ihrh"))
		return true;
	if (MATCHSTR(payload, "ihrj"))
		return true;
	if (MATCHSTR(payload, "ihro"))
		return true;
	if (MATCHSTR(payload, "iiro"))
		return true;
	if (MATCHSTR(payload, "ikri"))
		return true;
	if (MATCHSTR(payload, "ikvk"))
		return true;

	return false;

}

static inline bool match_fortinet_resp(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
	if (len == 36 && MATCHSTR(payload, "kowO"))
		return true;
	if (len == 44 && MATCHSTR(payload, "kowG"))
		return true;
	if (len == 12 && MATCHSTR(payload, "nkwg"))
		return true;
	if (len == 32 && MATCHSTR(payload, "khwK"))
		return true;
	return false;

}

static inline bool match_fortinet(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Seems to be part of the Fortinet update system */
	if (match_fortinet_req(data->payload[0], data->payload_len[0])) {
		if (match_fortinet_resp(data->payload[1], data->payload_len[1]))
			return true;
	}
	if (match_fortinet_req(data->payload[1], data->payload_len[1])) {
		if (match_fortinet_resp(data->payload[0], data->payload_len[0]))
			return true;
	}


	if (match_str_either(data, "Comm")) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}

	return false;
}

static lpi_module_t lpi_fortinet = {
	LPI_PROTO_UDP_FORTINET,
	LPI_CATEGORY_SECURITY,
	"Fortinet",
	3,
	match_fortinet
};

void register_fortinet(LPIModuleMap *mod_map) {
	register_protocol(&lpi_fortinet, mod_map);
}

