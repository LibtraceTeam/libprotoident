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

static inline bool match_lifeforge_login(uint32_t payload, uint32_t len) {

        uint32_t plen = bswap_le_to_host32(payload);

        /* I've only seen 0x25 in here, but that may vary depending on
         * username length? */
        if (MATCH(payload, ANY, 0x00, 0x00, 0x00)) {
                if (len == plen + 4)
                        return true;
        }

        return false;
}

static inline bool match_lifeforge_ping(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x0e, 0x00, 0x00, 0x00)) {
                if (len == 18)
                        return true;
                if (len == 34)
                        return true;
        }

        return false;

}

static inline bool match_lifeforge(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_lifeforge_login(data->payload[0], data->payload_len[0])) {
                if (match_lifeforge_ping(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_lifeforge_login(data->payload[1], data->payload_len[1])) {
                if (match_lifeforge_ping(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_lifeforge = {
	LPI_PROTO_LIFEFORGE,
	LPI_CATEGORY_GAMING,
	"LifeForge",
	150,
	match_lifeforge
};

void register_lifeforge(LPIModuleMap *mod_map) {
	register_protocol(&lpi_lifeforge, mod_map);
}

