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

static inline bool match_dvrns_typea(uint32_t payload_a, uint32_t len_a,
		uint32_t payload_b, uint32_t len_b) {

	if (!MATCH(payload_a, 0x12, 0xa4, 0x00, 0x01))
		return false;
	if (len_a != 188)
		return false;
	if (len_b == 0)
		return true;
	if (len_b != 20)
		return false;
	if (!MATCH(payload_b, 0x12, 0xa4, 0x00, 0x01))
		return false;
	return true;

}

static inline bool match_dvrns_typeb(uint32_t payload_a, uint32_t len_a,
		uint32_t payload_b, uint32_t len_b) {

	if (!MATCH(payload_a, 0x12, 0xa4, 0x00, 0x01))
		return false;
	if (len_a != 12)
		return false;
	if (len_b == 0)
		return true;
	if (len_b != 140)
		return false;
	if (!MATCH(payload_b, 0x12, 0xa4, 0x00, 0x01))
		return false;
	return true;

}

static inline bool match_dvrns(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* DVRNS is basically DNS for DVR surveillance systems */

	/* Not sure whether this is just the protocol used by dvrnames.net
	 * or all DVRNS systems */

	if (match_dvrns_typea(data->payload[0], data->payload_len[0],
			data->payload[1], data->payload_len[1]))
		return true;
	if (match_dvrns_typea(data->payload[1], data->payload_len[1],
			data->payload[0], data->payload_len[0]))
		return true;
	if (match_dvrns_typeb(data->payload[0], data->payload_len[0],
			data->payload[1], data->payload_len[1]))
		return true;
	if (match_dvrns_typeb(data->payload[1], data->payload_len[1],
			data->payload[0], data->payload_len[0]))
		return true;

	return false;
}

static lpi_module_t lpi_dvrns = {
	LPI_PROTO_DVRNS,
	LPI_CATEGORY_SERVICES,
	"DVRNS",
	10,
	match_dvrns
};

void register_dvrns(LPIModuleMap *mod_map) {
	register_protocol(&lpi_dvrns, mod_map);
}

