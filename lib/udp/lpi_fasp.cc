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

static inline bool match_fasp_out(uint32_t payload, uint32_t len) {

	if (MATCH(payload, ANY, 0x21, 0x00, 0x00))
		return true;

	return false;

}

static inline bool match_fasp_in(uint32_t payload, uint32_t len) {
	
	if (len != 64)
		return false;

	if (MATCH(payload, ANY, 0x20, 0x00, 0x00))
		return true;
	
	return false;

}

static inline bool match_fasp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->server_port != 33001 && data->client_port != 33001)
		return false;
	
	/* First byte must match in both directions */
	if ((data->payload[0] & 0xff) != (data->payload[1] & 0xff))
		return false;

	if (match_fasp_out(data->payload[0], data->payload_len[0])) {
		if (match_fasp_in(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_fasp_out(data->payload[1], data->payload_len[1])) {
		if (match_fasp_in(data->payload[0], data->payload_len[0]))
			return true;
	}
	return false;
}

static lpi_module_t lpi_fasp = {
	LPI_PROTO_UDP_FASP,
	LPI_CATEGORY_FILES,
	"FASP",
	16,
	match_fasp
};

void register_fasp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_fasp, mod_map);
}

