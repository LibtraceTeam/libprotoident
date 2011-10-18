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

static inline bool match_cisco_vpn_payload(uint32_t payload, uint32_t len) {
	if (len == 0)
		return true;
	if (MATCH(payload, 0x01, 0xf4, 0x01, 0xf4))
		return true;
	return false;
}

static inline bool match_cisco_vpn(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!match_cisco_vpn_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_cisco_vpn_payload(data->payload[1], data->payload_len[1]))
		return false;

	return true;
}

static lpi_module_t lpi_cisco_vpn = {
	LPI_PROTO_CISCO_VPN,
	LPI_CATEGORY_TUNNELLING,
	"Cisco_VPN",
	3,
	match_cisco_vpn
};

void register_cisco_vpn(LPIModuleMap *mod_map) {
	register_protocol(&lpi_cisco_vpn, mod_map);
}

