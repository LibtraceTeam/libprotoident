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

/* Destiny -- multiplayer FPS by Bungie */

static inline bool match_destiny_request(uint32_t payload, uint32_t len) {
        if (len == 140 && MATCH(payload, 0x01, 0x02, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_destiny_reply(uint32_t payload, uint32_t len) {
        if (len == 142 && MATCH(payload, 0x01, 0x02, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_destiny(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_destiny_request(data->payload[0], data->payload_len[0])) {
                if (match_destiny_reply(data->payload[1], data->payload_len[1]))
                        return true;
        }


        if (match_destiny_request(data->payload[1], data->payload_len[1])) {
                if (match_destiny_reply(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_destiny = {
	LPI_PROTO_DESTINY,
	LPI_CATEGORY_GAMING,
	"Destiny",
	23,
	match_destiny
};

void register_destiny(LPIModuleMap *mod_map) {
	register_protocol(&lpi_destiny, mod_map);
}

