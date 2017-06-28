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

static inline bool match_thecrew_hello(uint32_t payload, uint32_t len) {

        if (MATCHSTR(payload, "\xff\xff\xff\xff")) {
                if (len == 50)
                        return true;
                if (len == 39)
                        return true;
                if (len == 60)
                        return true;
        }
        return false;

}

static inline bool match_thecrew(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->server_port != 3001 && data->client_port != 3001)
                return false;

        if (match_thecrew_hello(data->payload[0], data->payload_len[0])) {
                if (match_thecrew_hello(data->payload[1], data->payload_len[1]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_thecrew = {
	LPI_PROTO_UDP_THE_CREW,
	LPI_CATEGORY_GAMING,
	"TheCrew",
	75,
	match_thecrew
};

void register_thecrew(LPIModuleMap *mod_map) {
	register_protocol(&lpi_thecrew, mod_map);
}

