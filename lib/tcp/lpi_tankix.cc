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

static inline bool match_tankix_19(uint32_t payload, uint32_t len) {

        if (MATCHSTR(payload, "\xff\x00\x00\x00") && len == 19)
                return true;
        return false;
}


static inline bool match_tankix(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Port 5050 */
        if (match_tankix_19(data->payload[0], data->payload_len[0])) {
                if (MATCHSTR(data->payload[1], "\xff\x00\x00\x00"))
                        return true;
        }

        if (match_tankix_19(data->payload[1], data->payload_len[1])) {
                if (MATCHSTR(data->payload[0], "\xff\x00\x00\x00"))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_tankix = {
	LPI_PROTO_TANKIX,
	LPI_CATEGORY_GAMING,
	"TankiX",
	52,
	match_tankix
};

void register_tankix(LPIModuleMap *mod_map) {
	register_protocol(&lpi_tankix, mod_map);
}

