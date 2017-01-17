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

static inline bool match_id(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* TODO: Starts with only digits - request matches the response  */
	
	/* 20 3a 20 55 is an ID protocol error, I think */
	if (match_str_either(data, " : U"))
		return true;

	return false;
}

static lpi_module_t lpi_id = {
	LPI_PROTO_ID,
	LPI_CATEGORY_SERVICES,
	"ID_Protocol",
	3,
	match_id
};

void register_id(LPIModuleMap *mod_map) {
	register_protocol(&lpi_id, mod_map);
}

