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

static inline bool match_command(uint32_t payload) {

	// no op
	if (MATCH(payload, 0x00, 0x00, ANY, ANY))
		return true;
	// list services
	if (MATCH(payload, 0x04, 0x00, ANY, ANY))
		return true;
	// list identity
	if (MATCH(payload, 0x63, 0x00, ANY, ANY))
		return true;
	// list interfaces
	if (MATCH(payload, 0x64, 0x00, ANY, ANY))
		return true;
	// register session
	if (MATCH(payload, 0x65, 0x00, 0x04, 0x00))
		return true;
	// un-register session
	if (MATCH(payload, 0x66, 0x00, ANY, ANY))
		return true;
	// sendrrdata
	if (MATCH(payload, 0x6f, 0x00, ANY, ANY))
		return true;
	// send unit data
	if (MATCH(payload, 0x70, 0x00, ANY, ANY))
		return true;
	// indicate status
	if (MATCH(payload, 0x72, 0x00, ANY, ANY))
		return true;
	// cancel
	if (MATCH(payload, 0x73, 0x00, ANY, ANY))
		return true;
	// error
	if (MATCH(payload, 0xff, 0xff, ANY, ANY))
		return true;

	return false;
}

static inline bool match_ethernetip(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->payload_len[0] < 24 || data->payload_len[1] < 24)
		return false;

	if (data->server_port != 44818 && data->client_port != 44818)
		return false;

	if (match_command(data->payload[0]) && match_command(data->payload[1]))
		return true;

	return false;
}

static lpi_module_t lpi_ethernetip = {
	LPI_PROTO_ETHERNETIP,
	LPI_CATEGORY_ICS,
	"EtherNet/IP",
	100,
	match_ethernetip
};

void register_ethernetip(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ethernetip, mod_map);
}
