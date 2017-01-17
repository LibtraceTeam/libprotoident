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

/* League of Legends: a popular online game circa 2012/2013 */
static inline bool match_lol(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if ((data->server_port < 5100 || data->server_port > 5150) &&
                        (data->client_port < 5100 || data->client_port > 5150))
                return false;

	if (data->payload_len[0] == 44 && data->payload_len[1] == 48)
		return true;
	if (data->payload_len[1] == 44 && data->payload_len[0] == 48)
		return true;

	if (data->payload_len[0] == 52 && data->payload_len[1] == 48)
		return true;
	if (data->payload_len[1] == 52 && data->payload_len[0] == 48)
		return true;

	return false;
}

static lpi_module_t lpi_lol = {
	LPI_PROTO_UDP_LOL,
	LPI_CATEGORY_GAMING,
	"LeagueOfLegends",
	35,
	match_lol
};

void register_lol(LPIModuleMap *mod_map) {
	register_protocol(&lpi_lol, mod_map);
}

