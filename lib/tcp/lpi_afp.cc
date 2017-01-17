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

static inline bool match_afp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Looking for a DSI header - command 4 is OpenSession */
        if (match_str_both(data, "\x00\x04\x00\x01", "\x01\x04\x00\x01"))
                return true;

	return false;
}

static lpi_module_t lpi_afp = {
	LPI_PROTO_AFP,
	LPI_CATEGORY_FILES,
	"AFP",
	5,
	match_afp
};

void register_afp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_afp, mod_map);
}

