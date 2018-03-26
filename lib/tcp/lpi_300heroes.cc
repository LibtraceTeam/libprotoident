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

/* Yet another Chinese LoL clone */

static inline bool match_heroes_c1(uint32_t payload, uint32_t len) {
        if (len == 12 && MATCH(payload, 0xc1, 0x0c, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_heroes_c2(uint32_t payload, uint32_t len) {
        if (len == 15 && MATCH(payload, 0xc2, 0x0f, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_heroes_db(uint32_t payload, uint32_t len) {
        if (len == 22 && MATCH(payload, 0xdb, 0x16, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_heroes_e7(uint32_t payload, uint32_t len) {
        if (MATCH(payload, 0xe7, 0x2a, 0x00, 0x00)) {
                if (len >= 185 && len <= 200)
                        return true;
        }
        return false;
}

static inline bool match_300heroes(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_heroes_c1(data->payload[0], data->payload_len[0])) {
                if (match_heroes_c2(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_heroes_c1(data->payload[1], data->payload_len[1])) {
                if (match_heroes_c2(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_heroes_db(data->payload[0], data->payload_len[0])) {
                if (match_heroes_e7(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_heroes_db(data->payload[1], data->payload_len[1])) {
                if (match_heroes_e7(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_300heroes = {
	LPI_PROTO_300_HEROES,
	LPI_CATEGORY_GAMING,
	"300Heroes",
	101,
	match_300heroes
};

void register_300heroes(LPIModuleMap *mod_map) {
	register_protocol(&lpi_300heroes, mod_map);
}

