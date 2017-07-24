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

static inline bool match_bao(uint32_t payload, uint32_t len) {
        uint32_t first = ntohl(payload) >> 24;

        if (len < 38 || len > 55)
                return false;

        /* First byte always begins with 0x2X or 0x3X */
        if (first < 0x20 || first > 0x3f)
                return false;

        return true;
}

static inline bool match_baofeng_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->server_port != 9909 && data->client_port != 9909)
                return false;

        if (match_bao(data->payload[0], data->payload_len[0])) {
                if (match_bao(data->payload[1], data->payload_len[1]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_baofeng_udp = {
	LPI_PROTO_UDP_BAOFENG,
	LPI_CATEGORY_STREAMING,
	"Baofeng",
	105,
	match_baofeng_udp
};

void register_baofeng_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_baofeng_udp, mod_map);
}

