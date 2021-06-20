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

/* destination mac addresses for valid LLMNR packets */
static uint8_t IP6_LLMNR[6] = {0x33, 0x33, 0x00, 0x01, 0x00, 0x03};
static uint8_t IP4_LLMNR[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFC};

#define OPCODE(x) ((x & 0x7800) >> 11)
#define SESSION_ID(x) (x & 0xFFFF0000)
#define MATCH_MAC(x, y) (!memcmp(x, y, 6))

static inline bool match_llmnr(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->server_port != 5355 && data->client_port != 5355)
		return false;

	/* session id should match between request/response */
	if (SESSION_ID(data->payload[0]) != SESSION_ID(data->payload[1]))
		return false;

	/* the opcode should match between request/response */
	if (OPCODE(data->payload[0]) != OPCODE(data->payload[1]))
		return false;

	if (data->trans_proto != TRACE_IPPROTO_UDP)
		return false;

	if (!MATCH_MAC(data->macs[0], IP4_LLMNR) &&
		!MATCH_MAC(data->macs[0], IP6_LLMNR) &&
		!MATCH_MAC(data->macs[1], IP4_LLMNR) &&
		!MATCH_MAC(data->macs[1], IP6_LLMNR))

		return false;

	return true;
}

static lpi_module_t lpi_llmnr = {
	LPI_PROTO_UDP_LLMNR,
	LPI_CATEGORY_SERVICES,
	"LLMNR",
	200,
	match_llmnr
};

void register_llmnr(LPIModuleMap *mod_map) {
	register_protocol(&lpi_llmnr, mod_map);
}

