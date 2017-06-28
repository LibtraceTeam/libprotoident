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

static inline bool match_gow_44(uint32_t payload, uint32_t len) {
        if (MATCH(payload, 0x00, 0x00, 0x00, 0x00) && len == 44)
                return true;
        return false;
}

static inline bool match_gow_51(uint32_t payload, uint32_t len) {
        if (MATCH(payload, 0x00, 0x00, 0x00, 0x00) && len == 51)
                return true;
        return false;
}

static inline bool match_gow_port(uint32_t sp, uint32_t cp) {

        if (sp == 30200 || cp == 30200)
                return true;
        if (sp == 30400 || cp == 30400)
                return true;
        if (sp == 30600 || cp == 30600)
                return true;
        if (sp == 31000 || cp == 31000)
                return true;
        if (sp == 30800 || cp == 30800)
                return true;
        if (sp == 30000 || cp == 30000)
                return true;

        return false;
}

static inline bool match_gearsofwar(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (!match_gow_port(data->server_port, data->client_port))
                return false;

        if (match_gow_44(data->payload[0], data->payload_len[0])) {
                if (match_gow_51(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_gow_44(data->payload[1], data->payload_len[1])) {
                if (match_gow_51(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_gearsofwar = {
	LPI_PROTO_UDP_GEARSOFWAR,
	LPI_CATEGORY_GAMING,
	"GearsOfWar",
	199,
	match_gearsofwar
};

void register_gearsofwar(LPIModuleMap *mod_map) {
	register_protocol(&lpi_gearsofwar, mod_map);
}

