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

/* TenSafe is an anti-cheat mechanism that is included with major
 * online games published by Tencent, e.g. Blade N Soul, DNF.
 */

static inline bool match_tensafe_req(uint32_t payload, uint32_t len) {
        if (len != 42)
                return false;
        if (MATCH(payload, 0x01, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_tensafe_resp(uint32_t payload, uint32_t len) {
        if (len == 0)
                return true;

        if (len != 50)
                return false;
        if (MATCH(payload, 0x01, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool is_tensafe_port(uint16_t server, uint16_t client) {
        if (server == 8080 || server == 80 || server == 443)
                return true;
        if (server == 10012)
                return true;
        if (client == 8080 || client == 80 || client == 443)
                return true;
        if (client == 10012)
                return true;
        return false;
}

static inline bool match_tensafe(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (!is_tensafe_port(data->server_port, data->client_port))
                return false;

        if (match_tensafe_req(data->payload[0], data->payload_len[0])) {
                if (match_tensafe_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_tensafe_req(data->payload[1], data->payload_len[1])) {
                if (match_tensafe_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_tensafe = {
	LPI_PROTO_TENSAFE,
	LPI_CATEGORY_GAMING,
	"TenSafe",
	70,
	match_tensafe
};

void register_tensafe(LPIModuleMap *mod_map) {
	register_protocol(&lpi_tensafe, mod_map);
}

