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

static inline bool match_goe_gnp(uint32_t payload, uint32_t len) {
        if (len == 8 && MATCH(payload, 'G', 'N', 'P', '1'))
                return true;
        return false;
}

static inline bool match_goe_binary(uint32_t payload, uint32_t len) {

        if (len >= 275 && len <= 300) {
                if (MATCH(payload, 0x01, 0x02, 0x00, 0x01))
                        return true;
                if (MATCH(payload, 0x01, 0x03, 0x00, 0x01))
                        return true;

        }
        return false;

}


static inline bool match_graalonlineera(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Port 14900 */

        if (match_goe_gnp(data->payload[0], data->payload_len[0])) {
                if (match_goe_binary(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_goe_gnp(data->payload[1], data->payload_len[1])) {
                if (match_goe_binary(data->payload[0], data->payload_len[0]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_graalonlineera = {
	LPI_PROTO_GRAAL_ONLINE_ERA,
	LPI_CATEGORY_GAMING,
	"GraalOnlineEra",
	8,
	match_graalonlineera
};

void register_graalonlineera(LPIModuleMap *mod_map) {
	register_protocol(&lpi_graalonlineera, mod_map);
}

