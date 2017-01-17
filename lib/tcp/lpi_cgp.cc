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

static inline bool match_cgp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Citrix CGP is a special version of ICA that runs on TCP port
	 * 2598 */

	if (match_str_both(data, "\x1a""CGP", "\x1a""CGP"))
		return true;

	return false;
}

static lpi_module_t lpi_cgp = {
	LPI_PROTO_CGP,
	LPI_CATEGORY_REMOTE,
	"CitrixCGP",
	3,
	match_cgp
};

void register_cgp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_cgp, mod_map);
}

