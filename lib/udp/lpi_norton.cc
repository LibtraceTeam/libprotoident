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

static inline bool match_norton_24_00(uint32_t payload, uint32_t len) {

	if (len != 24)
		return false;
	if (MATCH(payload, 0x00, 0x10, 0x00, 0x14))
		return true;
	return false;

}

static inline bool match_norton_24_80(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
	if (len != 24)
		return false;
	if (MATCH(payload, 0x80, 0x10, 0x00, 0x14))
		return true;
	return false;

}


static inline bool match_norton(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (MATCH(data->payload[0], 0x02, 0x0a, 0x00, 0xc0)) {
                if (data->payload_len[0] != 16)
                        return false;
                if (data->payload_len[1] != 0)
                        return false;
                return true;
        }
        if (MATCH(data->payload[1], 0x02, 0x0a, 0x00, 0xc0)) {
                if (data->payload_len[1] != 16)
                        return false;
                if (data->payload_len[0] != 0)
                        return false;
                return true;
        }
	

	/* New behaviour observed in 2012 - interesting use of port 53 */
	if (match_norton_24_00(data->payload[0], data->payload_len[0])) {
		
		if (data->server_port != 53 && data->client_port != 53)
			return false;

		if (match_norton_24_80(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_norton_24_00(data->payload[1], data->payload_len[1])) {
		if (data->server_port != 53 && data->client_port != 53)
			return false;
		if (match_norton_24_80(data->payload[0], data->payload_len[0]))
			return true;
	}
	return false;
}

static lpi_module_t lpi_norton = {
	LPI_PROTO_UDP_NORTON,
	LPI_CATEGORY_SECURITY,
	"Norton_UDP",
	5,
	match_norton
};

void register_norton(LPIModuleMap *mod_map) {
	register_protocol(&lpi_norton, mod_map);
}

