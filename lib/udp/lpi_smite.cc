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


static inline bool match_smite(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        
        if (MATCH(data->payload[0], 0x01, 0x14, 0x00, 0x00)) {
                if (MATCH(data->payload[1], 0x01, 0x14, 0x00, 0x00)) {
                        if (data->payload_len[0] < 100 && data->payload_len[1] < 100)
                               return true;
                }
        }

	return false;
}

static lpi_module_t lpi_smite = {
	LPI_PROTO_UDP_SMITE,
	LPI_CATEGORY_GAMING,
	"Smite",
	55,
	match_smite
};

void register_smite(LPIModuleMap *mod_map) {
	register_protocol(&lpi_smite, mod_map);
}

