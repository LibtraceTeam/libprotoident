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

#define PDU_TYPE(x) (data->payload[0] & 0xff0000) >> 16

static inline bool match_rpc(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->server_port != 135 && data->client_port != 135)
		return false;

	// valid PDUs are 0 - 19
	if (PDU_TYPE(data->payload[0]) > 19 || PDU_TYPE(data->payload[1]) > 19)
		return false;

	if (match_chars_both(data, 0x05, 0x00, ANY, 0x03))
		return true;

	return false;
}

static lpi_module_t lpi_rpc = {
	LPI_PROTO_RPC,
	LPI_CATEGORY_SERVICES,
	"RPC",
	200,
	match_rpc
};

void register_rpc(LPIModuleMap *mod_map) {
	register_protocol(&lpi_rpc, mod_map);
}

