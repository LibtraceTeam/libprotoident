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

/* This is a horrible pseudo-VPN that is used to access content that is
 * restricted to China only. Despite their claims, the traffic is not
 * encrypted -- just tunnelled over a custom UDP application protocol
 * to a server in Hong Kong.
 */

static inline bool match_n2ping_header(uint32_t payload) {

        if (MATCH(payload, 0x08, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_n2ping(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        bool validport = false;

        if (data->server_port == 44778 || data->client_port == 44778) {
                validport = true;
        }
        if (data->server_port == 23 || data->client_port == 23) {
                validport = true;
        }

        if (validport && match_n2ping_header(data->payload[0]) &&
                        match_n2ping_header(data->payload[1])) {
                if (data->payload_len[0] < 100)
                        return true;
                if (data->payload_len[1] < 100)
                        return true;
        }

	return false;
}

static lpi_module_t lpi_n2ping = {
	LPI_PROTO_UDP_N2PING,
	LPI_CATEGORY_TUNNELLING,
	"N2Ping",
	150,
	match_n2ping
};

void register_n2ping(LPIModuleMap *mod_map) {
	register_protocol(&lpi_n2ping, mod_map);
}

