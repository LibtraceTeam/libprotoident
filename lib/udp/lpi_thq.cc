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

static inline bool match_thq(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* I *suspect* this is the protocol used by RTS games released by
         * THQ - haven't been able to confirm for sure, though
         *
         * Most traffic is on port 6112, which is used by Blizzard and THQ
         * games, but we already have rules for most Blizzard stuff */

        /* The ANY byte also matches the packet length - 17, if we need 
         * further matching rules */
        if (data->payload_len[0] != 0 &&
                        !MATCH(data->payload[0], 'Q', 'N', 'A', ANY))
                return false;
        if (data->payload_len[1] != 0 &&
                        !MATCH(data->payload[1], 'Q', 'N', 'A', ANY))
                return false;

        return true;

}

static lpi_module_t lpi_thq = {
	LPI_PROTO_UDP_THQ,
	LPI_CATEGORY_GAMING,
	"THQ",
	3,
	match_thq
};

void register_thq(LPIModuleMap *mod_map) {
	register_protocol(&lpi_thq, mod_map);
}

