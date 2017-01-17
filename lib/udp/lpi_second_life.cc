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

static inline bool match_second_life_req(uint32_t payload, uint32_t len) {

	if (len != 46 && len != 54)
		return false;
	if (!MATCH(payload, 0x40, 0x00, 0x00, 0x00))
		return false;
	return true;

}

static inline bool match_second_life(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Haven't actually seen any legit 2-way SecondLife exchanges, so
	 * only speculating based on my interpretation of the specs
	 *
	 * http://wiki.secondlife.com/wiki/Packet_Layout
	 */

	if (match_second_life_req(data->payload[0], data->payload_len[0])) {
		if (data->payload_len[1] == 0)
			return true;
		if (MATCH(data->payload[1], ANY, 0x00, 0x00, 0x00)) {
			if (data->payload_len[1] < 15)
				return false;
			if ((data->payload_len[1] + 1) % 4 == 0)
				return true;
		}
	}

	if (match_second_life_req(data->payload[1], data->payload_len[1])) {
		if (data->payload_len[0] == 0)
			return true;
		if (MATCH(data->payload[0], ANY, 0x00, 0x00, 0x00)) {
			if (data->payload_len[0] < 15)
				return false;
			if ((data->payload_len[0] + 1) % 4 == 0)
				return true;
		}
	}
	return false;
}

static lpi_module_t lpi_second_life = {
	LPI_PROTO_UDP_SECONDLIFE,
	LPI_CATEGORY_GAMING,
	"SecondLife_UDP",
	6,
	match_second_life
};

void register_second_life_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_second_life, mod_map);
}

