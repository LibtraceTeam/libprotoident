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

static inline bool match_stun_payload(uint32_t payload, uint32_t len) {
        /* Bytes 3 and 4 are the Message Length - the STUN header */
        if ((ntohl(payload) & 0x0000ffff) != len - 20)
                return false;

        if (MATCH(payload, 0x00, 0x01, ANY, ANY))
                return true;
        if (MATCH(payload, 0x01, 0x01, ANY, ANY))
                return true;
        if (MATCH(payload, 0x01, 0x11, ANY, ANY))
                return true;
        if (MATCH(payload, 0x00, 0x03, ANY, ANY))
                return true;
        if (MATCH(payload, 0x01, 0x03, ANY, ANY))
                return true;
        if (MATCH(payload, 0x01, 0x13, ANY, ANY))
                return true;

        return false;

}


static inline bool match_stun_tcp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Wouldn't have expected to see STUN over TCP, but sure we can 
	 * match that. */

	if (match_str_either(data, "RSP/"))
		return true;

        /* We can also see more conventional STUN payloads over TCP as well :/
         */
        if (data->server_port == 3478 || data->client_port == 3478) {
                if (match_stun_payload(data->payload[0], data->payload_len[0]))
                {
                        if (match_stun_payload(data->payload[1],
                                                data->payload_len[1])) {
                                return true;
                        }
                }
        }

	return false;
}

static lpi_module_t lpi_stun_tcp = {
	LPI_PROTO_STUN,
	LPI_CATEGORY_NAT,
	"STUN_TCP",
	5,
	match_stun_tcp
};

void register_stun_tcp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_stun_tcp, mod_map);
}

