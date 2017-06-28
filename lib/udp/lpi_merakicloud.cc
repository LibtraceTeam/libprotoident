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


static inline bool match_merakicloud(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Port 7351 */

        /* This may just be a user id of some sort -- need to see multiple
         * users to confirm this is a fixed pattern.
         */
        if (MATCH(data->payload[0], 0xfe, 0xf7, 0x28, 0x91)) {
                if (MATCH(data->payload[1], 0xfe, 0xf7, 0x28, 0x91)) {
                        return true;
                }
        }

	return false;
}

static lpi_module_t lpi_merakicloud = {
	LPI_PROTO_UDP_MERAKICLOUD,
	LPI_CATEGORY_CLOUD,
	"MerakiCloud",
	34,
	match_merakicloud
};

void register_merakicloud(LPIModuleMap *mod_map) {
	register_protocol(&lpi_merakicloud, mod_map);
}

