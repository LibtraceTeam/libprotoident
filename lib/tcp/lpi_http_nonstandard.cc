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

static inline bool match_nonstandard_http(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Must not be on a known HTTP port
         * 
	 * This used to be HTTP_P2P, but we found that most of this stuff was
	 * legit HTTP - just using really weird ports.
	 *
	 * We might miss some HTTP-based P2P now, but it's just too hard for
	 * us to differentiate more than this.
	 */
        if (valid_http_port(data))
                return false;

        if (match_str_both(data, "GET ", "HTTP"))
                return true;

        if (match_str_either(data, "GET ")) {
                if (data->payload_len[0] == 0 || data->payload_len[1] == 0)
                        return true;
        }

        return false;
}

static lpi_module_t lpi_http_nonstandard = {
	LPI_PROTO_NONSTANDARD_HTTP,
	LPI_CATEGORY_WEB,
	"HTTP_NonStandard",
	100,
	match_nonstandard_http
};

void register_http_nonstandard(LPIModuleMap *mod_map) {
	register_protocol(&lpi_http_nonstandard, mod_map);
}

