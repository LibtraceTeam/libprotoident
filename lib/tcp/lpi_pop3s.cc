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

static inline bool match_pop3s(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!match_ssl(data))
		return false;
	
	/* Assume all SSL traffic on port 995 is POP3S */
	if (data->server_port == 995 || data->client_port == 995)
		return true;
	
	return false;
}

static lpi_module_t lpi_pop3s = {
	LPI_PROTO_POP3S,
	LPI_CATEGORY_MAIL,
	"POP3S",
	2, /* Should be a higher priority than regular SSL */
	match_pop3s
};

void register_pop3s(LPIModuleMap *mod_map) {
	register_protocol(&lpi_pop3s, mod_map);
}

