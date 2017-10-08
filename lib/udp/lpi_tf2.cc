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

static inline bool match_tf2_20(uint32_t payload, uint32_t len) {
        if (len == 20 && MATCHSTR(payload, "\xff\xff\xff\xff"))
                return true;
        return false;
}

static inline bool match_tf2_39(uint32_t payload, uint32_t len) {
        if (len == 39 && MATCHSTR(payload, "\xff\xff\xff\xff"))
                return true;
        return false;
}

static inline bool is_okport(lpi_data_t *data) {
        if (data->server_port == 27015 && data->client_port == 27015)
                return true;
        if (data->server_port == 27005 || data->client_port == 27005)
                return true;
        return false;
}

static inline bool match_tf2(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (!is_okport(data))
                return false;

        if (match_tf2_20(data->payload[0], data->payload_len[0])) {
                if (match_tf2_39(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_tf2_20(data->payload[1], data->payload_len[1])) {
                if (match_tf2_39(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_tf2 = {
	LPI_PROTO_UDP_TF2,
	LPI_CATEGORY_GAMING,
	"TeamFortress2",
	100,
	match_tf2
};

void register_tf2(LPIModuleMap *mod_map) {
	register_protocol(&lpi_tf2, mod_map);
}

