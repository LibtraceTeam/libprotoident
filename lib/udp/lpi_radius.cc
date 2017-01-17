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

static inline bool match_radius_request(uint32_t pload, uint32_t len) {

	uint32_t stated_len = 0;

	stated_len = ntohl(pload) & 0xffff;
	if (stated_len != len)
		return false;
	
	/* Access-Request */
	if (MATCH(pload, 0x01, ANY, ANY, ANY))
		return true;
	/* Accounting-Request */
	if (MATCH(pload, 0x04, ANY, ANY, ANY))
		return true;

	return false;
}

static inline bool match_radius_resp(uint32_t pload, uint32_t len) {

	uint32_t stated_len = 0;

	stated_len = ntohl(pload) & 0xffff;
	if (stated_len != len)
		return false;

	/* Access-Accept */	
	if (MATCH(pload, 0x02, ANY, ANY, ANY))
		return true;
	/* Access-Reject */
	if (MATCH(pload, 0x03, ANY, ANY, ANY))
		return true;
	/* Accounting-Response */
	if (MATCH(pload, 0x05, ANY, ANY, ANY))
		return true;

	return false;
}

static inline bool match_radius(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	//if (data->server_port != 1812 && data->client_port != 1812)
	//	return false;

	/* Second byte is the ID field, which must match for both payloads */
	if ((ntohl(data->payload[0]) & 0xff0000) != 
			(ntohl(data->payload[1]) & 0xff0000))
		return false;

	if (match_radius_request(data->payload[0], data->payload_len[0])) {
		if (match_radius_resp(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_radius_request(data->payload[1], data->payload_len[1])) {
		if (match_radius_resp(data->payload[0], data->payload_len[0]))
			return true;
	}
	return false;
}

static lpi_module_t lpi_radius = {
	LPI_PROTO_UDP_RADIUS,
	LPI_CATEGORY_REMOTE,
	"Radius",
	14,
	match_radius
};

void register_radius(LPIModuleMap *mod_map) {
	register_protocol(&lpi_radius, mod_map);
}

