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
 * $Id: lpi_apple_facetime_init.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* Protocol used to talk to Apple servers when commencing a Facetime call.
 * iMessage may also use this protocol to determine whether iMessage is 
 * available between two devices.
 * May also be used by Game Center (but this is not verified).
 *
 * NOTE: this protocol is not used for the actual Facetime call itself - that
 * is done via RTP, SIP and other standard protocols.
 */

static inline bool match_afi_server_port(uint16_t port) {

	if (port < 16384)
		return false;
	if (port > 16387)
		return false;
	return true;
}

static inline bool match_afi_client_port(uint16_t port) {
	if (port < 16402)
		return false;
	if (port > 16410)
		return false;
	return true;
}

static inline bool match_facetime_req(uint32_t payload, uint32_t len) {
	
	if (len != 16)
		return false;
	if (MATCH(payload, 0x00, 0x01, 0x00, 0x02))
		return true;
	if (MATCH(payload, 0x00, 0x00, 0x00, 0x02))
		return true;
	return false;
}

static inline bool match_facetime_resp(uint32_t payload, uint32_t len) {
	
	if (len == 0)
		return true;
	if (len != 16)
		return false;
	if (MATCH(payload, 0x00, 0x01, 0x00, 0x01))
		return true;
	if (MATCH(payload, 0x00, 0x00, 0x00, 0x01))
		return true;
	return false;
}

static inline bool match_apple_facetime_init(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!match_afi_server_port(data->server_port) && 
			!match_afi_client_port(data->server_port)) {
		return false;
	}
	
	if (!match_afi_server_port(data->client_port) && 
			!match_afi_client_port(data->client_port)) {
		return false;
	}

	if (match_facetime_req(data->payload[0], data->payload_len[0])) {
		if (match_facetime_resp(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_facetime_req(data->payload[1], data->payload_len[1])) {
		if (match_facetime_resp(data->payload[0], data->payload_len[0]))
			return true;
	}
	return false;
}

static lpi_module_t lpi_apple_facetime_init = {
	LPI_PROTO_UDP_APPLE_FACETIME_INIT,
	LPI_CATEGORY_NAT,	// Unsure about this one...
	"AppleFacetimeInit",
	16,
	match_apple_facetime_init
};

void register_apple_facetime_init(LPIModuleMap *mod_map) {
	register_protocol(&lpi_apple_facetime_init, mod_map);
}

