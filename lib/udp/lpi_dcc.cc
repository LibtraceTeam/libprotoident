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

/* DCC is the IRC-based file sharing protocol, not to be confused with
 * Direct Connect */

static inline bool match_dcc_length(uint32_t payload, uint32_t len) {

	uint32_t hdr_len;

	hdr_len = (ntohl(payload)) >> 16;

	if (hdr_len == len)
		return true;
	return false;

}

static inline bool match_dcc_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!match_dcc_length(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_dcc_length(data->payload[1], data->payload_len[1]))
		return false;

	/* Byte 3 must match */
	if ((ntohl(data->payload[0]) & 0xff00) != (ntohl(data->payload[1]) & 0xff00))
		return false;

	if (MATCH(data->payload[0], ANY, ANY, ANY, 0x01)) {
		if (MATCH(data->payload[1], ANY, ANY, ANY, 0x06))
			return true;
	}
	
	if (MATCH(data->payload[1], ANY, ANY, ANY, 0x01)) {
		if (MATCH(data->payload[0], ANY, ANY, ANY, 0x06))
			return true;
	}

	if (MATCH(data->payload[0], ANY, ANY, ANY, 0x02)) {
		if (MATCH(data->payload[1], ANY, ANY, ANY, 0x04))
			return true;
	}
	
	if (MATCH(data->payload[1], ANY, ANY, ANY, 0x02)) {
		if (MATCH(data->payload[0], ANY, ANY, ANY, 0x04))
			return true;
	}

	return false;
}

static lpi_module_t lpi_dcc_udp = {
	LPI_PROTO_UDP_DCC,
	LPI_CATEGORY_CHAT,
	"DCC_UDP",
	8,
	match_dcc_udp
};

void register_dcc_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_dcc_udp, mod_map);
}

