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
 * $Id: lpi_mdns.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* Multicast DNS */

static inline bool match_mdns(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->server_port != 5353)
		return false;
	if (data->client_port != 5353)
		return false;

	/* Flags are set */
	if (MATCH(data->payload[0], 0x00, 0x00, 0x84, 0x00)) {
		if (data->payload_len[1] == 0)
			return true;
	}
	if (MATCH(data->payload[1], 0x00, 0x00, 0x84, 0x00)) {
		if (data->payload_len[0] == 0)
			return true;
	}

	/* Flags are not set - this is tricky because the payload is zero */
	if (data->payload_len[0] != 0 && data->payload[0] == 0) {
		if (data->payload_len[1] == 0)
			return true;
	}
	if (data->payload_len[1] != 0 && data->payload[1] == 0) {
		if (data->payload_len[0] == 0)
			return true;
	}
		
	
	return false;
}

static lpi_module_t lpi_mdns = {
	LPI_PROTO_UDP_MDNS,
	LPI_CATEGORY_SERVICES,
	"mDNS",
	20,
	match_mdns
};

void register_mdns(LPIModuleMap *mod_map) {
	register_protocol(&lpi_mdns, mod_map);
}

