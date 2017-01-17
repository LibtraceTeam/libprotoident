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

static inline bool match_wolf_payload(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;
        if (!MATCH(payload, 0xff, 0xff, 0xff, 0xff))
                return false;
        return true;

}


static inline bool match_wolf_et(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Limit to port 27960 for now */
        if (data->server_port != 27960 && data->client_port != 27960)
                return false;

	if (!match_wolf_payload(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_wolf_payload(data->payload[1], data->payload_len[1]))
                return false;

        /* One packet is always 14 bytes, the other is always > 800 */
        if (data->payload_len[0] == 14) {
                if (data->payload_len[1] == 0 || data->payload_len[1] >= 800)
                        return true;
        }
        if (data->payload_len[1] == 14) {
                if (data->payload_len[0] == 0 || data->payload_len[0] >= 800)
                        return true;
        }


	return false;
}

static lpi_module_t lpi_wolfet = {
	LPI_PROTO_UDP_WOLF_ET,
	LPI_CATEGORY_GAMING,
	"WolfensteinEnemyTerritory",
	5,	/* Must be lower priority than Call of Duty */
	match_wolf_et
};

void register_wolfet(LPIModuleMap *mod_map) {
	register_protocol(&lpi_wolfet, mod_map);
}

