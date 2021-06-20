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

static inline bool match_ldap_payload(uint32_t payload, uint32_t len, uint16_t server_port) {
	
	uint8_t *byte = ((uint8_t *)&payload);
	uint16_t struct_len = 0;

	if (len == 0)
		return true;

	byte ++;
	
	// multibyte lengths?
	if (((*byte) & 0x80) == 0x80) {
		uint8_t bytes_required = ((*byte) & 0x7f);
		if (bytes_required == 0)
			return false;

		if (bytes_required == 1) {
			if (len > 255)
				return false;
			byte ++;
			struct_len = 3 + ((uint8_t)(*byte));
			if (!MATCH(payload, 0x30, ANY, ANY, 0x02))
				return false;
		} else if (bytes_required == 2) {
			struct_len = 4 + ntohs(*((uint16_t *)(byte + 1)));
			if (!MATCH(payload, 0x30, ANY, ANY, ANY))
				return false;
		} else {
			// the length is now past the first 4 bytes of payload so we are unable
			// to check it, fallback to port in this case
			if (server_port == 389)
				return true;
		}
	} else {
		if (!MATCH(payload, 0x30, ANY, 0x02, 0x01))
			return false;
		if (len > 255)
			return false;
		struct_len = (*byte) + 2;
	}
			
	if (struct_len != len)
		return false;	
	

	return true;

}

static inline bool match_ldap(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!match_ldap_payload(data->payload[0], data->payload_len[0], data->server_port))
		return false;
	if (!match_ldap_payload(data->payload[1], data->payload_len[1], data->server_port))
		return false;

	return true;
}

static lpi_module_t lpi_ldap = {
	LPI_PROTO_LDAP,
	LPI_CATEGORY_SERVICES,
	"LDAP",
	3,
	match_ldap
};

void register_ldap(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ldap, mod_map);
}

