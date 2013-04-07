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

/* Thanks to Remy Mudingay for providing traces to identify this protocol */

static inline bool match_openvpn_handshake(uint32_t pl_a, uint32_t pl_b) {


	/* 0x31 and 0x37 are commonly used as the first byte of a UDP
	 * OpenVPN exchange. However, if one end uses 0x31 then the other
	 * must also use 0x31 -- same for 0x37. 
	 */

	if (MATCH(pl_a, 0x31, ANY, ANY, ANY)) {
		if (MATCH(pl_b, 0x31, ANY, ANY, ANY))
			return true;
	}
	
	if (MATCH(pl_a, 0x37, ANY, ANY, ANY)) {
		if (MATCH(pl_b, 0x37, ANY, ANY, ANY))
			return true;
	}
	
	
	return false;

}

static inline bool match_openvpn_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* The payload matching alone isn't very strong, so I'm going to
	 * add a port-based condition as well. Default port for OpenVPN
	 * is UDP 1194 */

	if (data->server_port != 1194 && data->client_port != 1194) {
		return false;
	}

	/* Just match the two-way stuff for now */
	if (match_openvpn_handshake(data->payload[0], data->payload[1])) 
		return true;
	return false;
}

static lpi_module_t lpi_openvpn_udp = {
	LPI_PROTO_UDP_OPENVPN,
	LPI_CATEGORY_TUNNELLING,
	"OpenVPN_UDP",
	12,
	match_openvpn_udp
};

void register_openvpn_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_openvpn_udp, mod_map);
}

