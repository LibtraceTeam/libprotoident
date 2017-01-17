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

static inline bool match_psn_store(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* This rule matches the SSL exchanges used by the Playstation
	 * Store */

	if (!match_ssl(data))
		return false;
	
	/* All PSN SSL traffic is on port 5223 */
	if (data->server_port != 5223 && data->client_port != 5223)
		return false;

	if (data->payload_len[0] == 66 && data->payload_len[1] == 1085)
		return true;
	if (data->payload_len[1] == 66 && data->payload_len[0] == 1085)
		return true;
	
	return false;
}

static lpi_module_t lpi_psn_store = {
	LPI_PROTO_PSN_STORE,
	LPI_CATEGORY_GAMING,
	"PSNStore",
	2, /* Should be a higher priority than regular SSL */
	match_psn_store
};

void register_psn_store(LPIModuleMap *mod_map) {
	register_protocol(&lpi_psn_store, mod_map);
}

