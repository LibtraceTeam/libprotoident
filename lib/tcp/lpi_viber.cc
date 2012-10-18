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
 * $Id: lpi_viber.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* I'm fairly confident this is viber - uses port 5242, destination is an
 * Amazon AWS server. Hard to test because capturing mobile traffic is much
 * trickier than capturing a desktop app */

static inline bool match_viber_in(uint32_t payload, uint32_t len) {

	/* First two bytes are length, but we only support one packet
	 * type right now anyway */

	if (len != 24)
		return false;
	if (MATCH(payload, 0x18, 0x00, 0x00, 0x00))
		return true;
	return false;

}

static inline bool match_viber_out(uint32_t payload, uint32_t len) {

	/* Again, bytes 1 and 2 are the length */
	if (len != 154)
		return false;
	if (MATCH(payload, 0x9a, 0x00, ANY, 0x00))
		return true;
	return false;

}

static inline bool match_viber(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Could enforce port 5242 if we're getting false positives */

	if (match_viber_in(data->payload[0], data->payload_len[0])) {
		if (match_viber_out(data->payload[1], data->payload_len[1])) {
			return true;
		}
		if (data->payload_len[1] == 0) {
			if (data->server_port == 5242 || data->client_port == 5242)
				return true;
		}
	}

	if (match_viber_in(data->payload[1], data->payload_len[1])) {
		if (match_viber_out(data->payload[0], data->payload_len[0])) {
			return true;
		}
		if (data->payload_len[0] == 0) {
			if (data->server_port == 5242 || data->client_port == 5242)
				return true;
		}
	}
	return false;
}

static lpi_module_t lpi_viber = {
	LPI_PROTO_VIBER,
	LPI_CATEGORY_VOIP,
	"Viber",
	9,
	match_viber
};

void register_viber(LPIModuleMap *mod_map) {
	register_protocol(&lpi_viber, mod_map);
}

