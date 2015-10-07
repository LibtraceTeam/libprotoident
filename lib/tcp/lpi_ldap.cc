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

static inline bool match_ldap_payload(uint32_t payload, uint32_t len) {
	
	uint8_t *byte = ((uint8_t *)&payload);
	uint16_t struct_len = 0;

	if (len == 0)
		return true;

	byte ++;
	
	if (((*byte) & 0x80) == 0x80) {
		uint8_t bytes_required = ((*byte) & 0x7f);
		if (bytes_required > 2 || bytes_required == 0)
			return false;

		if (bytes_required == 1) {
			if (len > 255)
				return false;
			byte ++;
			struct_len = 3 + ((uint8_t)(*byte));
			if (!MATCH(payload, 0x30, ANY, ANY, 0x02))
				return false;
		} else {
			struct_len = 4 + ntohs(*((uint16_t *)(byte + 1)));
			if (!MATCH(payload, 0x30, ANY, ANY, ANY))
				return false;
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

	if (!match_ldap_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_ldap_payload(data->payload[1], data->payload_len[1]))
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

