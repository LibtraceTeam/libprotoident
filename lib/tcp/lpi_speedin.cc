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

/* Speedin a.k.a. InVPN -- VPN for accessing Chinese content from outside
 * of China.
 */
static inline bool match_speedin_3byte(uint32_t payload, uint32_t len) {

        if (len == 3 && MATCH(payload, 0x00, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_speedin_other(uint32_t payload, uint32_t len) {
        if (len <= 75 || len >= 135)
                return false;

        if (MATCH(payload, 0x23, 0x00, ANY, ANY))
                return true;
        if (MATCH(payload, 0x03, 0x00, ANY, ANY))
                return true;
        return false;
}

static inline bool match_port(uint16_t server, uint16_t client) {
        if (server == 12000 || client == 12000)
                return true;

        if (server == 11100 || client == 11100)
                return true;
        if (server == 11000 || client == 11000)
                return true;

        return false;
}


static inline bool match_speedin(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (!match_port(data->server_port, data->client_port))
                return false;

        if (match_speedin_3byte(data->payload[0], data->payload_len[0])) {
                if (match_speedin_other(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_speedin_3byte(data->payload[1], data->payload_len[1])) {
                if (match_speedin_other(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_speedin = {
	LPI_PROTO_SPEEDIN,
	LPI_CATEGORY_TUNNELLING,
	"Speedin",
	22,
	match_speedin
};

void register_speedin(LPIModuleMap *mod_map) {
	register_protocol(&lpi_speedin, mod_map);
}

