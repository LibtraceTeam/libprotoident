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
 * $Id: lpi_ldap_ad.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_ldap_ad_payload(uint32_t payload, uint32_t len) {
	if (len == 0)
		return true;
	if (MATCH(payload, 0x30, 0x84, 0x00, 0x00))
		return true;
	return false;

}

static inline bool match_ldap_ad(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Rule out one-way DNS, which could look like our LDAP AD payload */
	if (data->payload_len[0] == 0 || data->payload_len[1] == 0) {
		if (data->server_port == 53 || data->client_port == 53)
			return false;
	}

	if (!match_ldap_ad_payload(data->payload[0], data->payload_len[0]))
		return false;	
	if (!match_ldap_ad_payload(data->payload[1], data->payload_len[1]))
		return false;	

	return true;
}

static lpi_module_t lpi_ldap_ad = {
	LPI_PROTO_UDP_LDAP_AD,
	LPI_CATEGORY_SERVICES,
	"LDAP_AD",
	5,
	match_ldap_ad
};

void register_ldap_ad(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ldap_ad, mod_map);
}

