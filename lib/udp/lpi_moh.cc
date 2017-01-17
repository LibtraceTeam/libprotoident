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

static inline bool match_moh_ping(lpi_data_t *data) {

        /* Seems to be server browsing for Medal of Honor: AA */

        if (match_str_both(data, "ping", "\xff\xff\xff\xff"))
                return true;

        if (MATCHSTR(data->payload[0], "ping")) {
                if (data->payload_len[0] != 4)
                        return false;
                if (data->payload_len[1] == 0)
                        return true;
        }

        if (MATCHSTR(data->payload[1], "ping")) {
                if (data->payload_len[1] != 4)
                        return false;
                if (data->payload_len[0] == 0)
                        return true;
        }

        return false;
}


static inline bool match_moh(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_moh_ping(data))
                return true;

        if (!MATCH(data->payload[0], 0xff, 0xff, 0xff, 0xff))
                return false;
        if (!MATCH(data->payload[1], 0xff, 0xff, 0xff, 0xff))
                return false;

        /* This is kinda a broad match, so let's refine it a bit by using the
         * port number */
        if (data->server_port >= 12200 && data->server_port <= 12210) {

                if (data->payload_len[0] == 16 && data->payload_len[1] > 600)
                        return true;
                if (data->payload_len[1] == 16 && data->payload_len[0] > 600)
                        return true;
        }

        if (data->client_port >= 12200 && data->client_port <= 12210) {

                if (data->payload_len[0] == 16 && data->payload_len[1] > 600)
                        return true;
                if (data->payload_len[1] == 16 && data->payload_len[0] > 600)
                        return true;
        }


	return false;
}

static lpi_module_t lpi_moh = {
	LPI_PROTO_UDP_MOH,
	LPI_CATEGORY_GAMING,
	"MedalOfHonor",
	8,
	match_moh
};

void register_moh(LPIModuleMap *mod_map) {
	register_protocol(&lpi_moh, mod_map);
}

