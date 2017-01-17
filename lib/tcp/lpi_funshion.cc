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
#include <stdio.h>

/* Funshion is a Chinese P2PTV application that seems to use a bunch
 * of different protocols / messages.
 */ 

static inline bool match_funshion_54(uint32_t payload, uint32_t len) {

	if (len != 54)
		return false;

	/* Byte 4 is always 0x00.
	 * Byte 3 is always 0x?1, where '?' can be any hex digit.
	 */
	if ((payload & 0xff0f0000) == 0x00010000)
		return true;
	
	return false;

}

static inline bool match_funshion_tcp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Only ever observed this traffic pattern on port 6601 */
	if (data->server_port == 6601 || data->client_port == 6601) {
		if (match_funshion_54(data->payload[0], data->payload_len[0])) {
			if (match_funshion_54(data->payload[1], data->payload_len[1]))
				return true;
		}
	}

        return false;

}

static lpi_module_t lpi_funshion_tcp = {
	LPI_PROTO_FUNSHION,
	LPI_CATEGORY_P2PTV,
	"Funshion_TCP",
	10,
	match_funshion_tcp
};

void register_funshion_tcp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_funshion_tcp, mod_map);
}

