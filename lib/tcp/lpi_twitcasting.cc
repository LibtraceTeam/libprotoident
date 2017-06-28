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

/* Live self-streaming protocol, popular in Japan */

static inline bool match_tc_get(uint32_t payload) {
        /* Yes, they have managed to co-opt "GET" for this protocol */

        if (MATCH(payload, 'G', 'E', 'T', 0x20))
                return true;
        return false;
}

static inline bool match_tc_reply(uint32_t payload, uint32_t len) {

        /* Possible that bytes 3 and 4 are a length field? */

        if (len == 19 && MATCH(payload, 'T', 'C', 0x0c, 0x00))
                return true;
        return false;

}

static inline bool match_twitcasting(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Can use port 8094 if we need to */

        if (match_tc_get(data->payload[0])) {
                if (match_tc_reply(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_tc_get(data->payload[0])) {
                if (match_tc_reply(data->payload[1], data->payload_len[1]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_twitcasting = {
	LPI_PROTO_TWITCASTING,
	LPI_CATEGORY_STREAMING,
	"TwitCasting",
	25,             /* Should definitely be higher than HTTP */
	match_twitcasting
};

void register_twitcasting(LPIModuleMap *mod_map) {
	register_protocol(&lpi_twitcasting, mod_map);
}

