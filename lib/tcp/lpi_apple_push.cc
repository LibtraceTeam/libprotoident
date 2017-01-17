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

static inline bool match_apple_push(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* This rule matches the push notifications sent to IOS devices */ 

	if (!match_ssl(data))
		return false;
	
	/* Port 5223 is used for the push notifications */
	if (data->server_port != 5223 && data->client_port != 5223)
		return false;

	/* If payload is only one-way, fall back to SSL to avoid risking
	 * a false positive for other port 5223 SSL apps, e.g. Kik */
	if (data->payload_len[0] == 0 || data->payload_len[1] == 0)
		return false;

	/* Too much size variation to write a good set of rules based on
	 * payload sizes, just use this as the fallback option for all
	 * SSL traffic on 5223 that doesn't match something else, e.g.
	 * PSN store */

	return true;
}

static lpi_module_t lpi_apple_push = {
	LPI_PROTO_APPLE_PUSH,
	LPI_CATEGORY_NOTIFICATION,
	"ApplePush",
	8, /* Should be a higher priority than regular SSL, but lower than
	      anything else on port 5223  */
	match_apple_push
};

void register_apple_push(LPIModuleMap *mod_map) {
	register_protocol(&lpi_apple_push, mod_map);
}

