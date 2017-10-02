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

static inline bool possible_port(uint16_t porta, uint16_t portb) {
        /* Bit hax, but the payload alone doesn't exactly feel
         * unique. */
        if (porta >= 3300 && porta < 3400)
                return true;

        if (portb >= 3300 && portb < 3400)
                return true;
        return false;
}

/* Protocol used for pooled bitcoin mining */
static inline bool match_stratum(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Port can vary but usually something around 3357 */

        if (!possible_port(data->server_port, data->client_port))
                return false;

        if (MATCH(data->payload[0], '{', '"', 'i', 'd')) {
                if (MATCH(data->payload[1], '{', '"', 'i', 'd'))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_stratum = {
	LPI_PROTO_STRATUM,
	LPI_CATEGORY_ECOMMERCE,
	"Stratum",
	200,
	match_stratum
};

void register_stratum(LPIModuleMap *mod_map) {
	register_protocol(&lpi_stratum, mod_map);
}

