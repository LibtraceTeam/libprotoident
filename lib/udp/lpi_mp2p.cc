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

static inline bool match_mp2p_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* At least one of the endpoints needs to be on the known port */
        if (data->server_port != 41170 && data->client_port != 41170)
                return false;

        if (match_chars_either(data, 0x3d, 0x4a, 0xd9, ANY))
                return true;
        if (match_chars_either(data, 0x3e, 0x4a, 0xd9, ANY))
                return true;
        if (match_chars_either(data, 0x3d, 0x4b, 0xd9, ANY))
                return true;
        if (match_chars_either(data, 0x3e, 0x4b, 0xd9, ANY))
                return true;
        if (match_chars_either(data, ANY, 0x4b, 0xd9, 0x65))
                return true;
        if (match_chars_either(data, ANY, 0x4a, 0xd9, 0x65))
                return true;
        if (match_chars_either(data, ANY, 0x4a, 0xd6, 0x6f))
                return true;
        if (match_chars_either(data, ANY, 0x4a, 0xd6, 0x90))
                return true;


        /* Seeing a lot of these in flows using port 41170 both ways */

	/* Watch out for one-way DNS again */
        if (data->server_port == 53 || data->client_port == 53)
		return false;
	
	if (MATCH(data->payload[0], ANY, ANY, 0x00, 0x00) &&
                        data->payload_len[0] != 0) {
                if (data->payload_len[1] != 0)
                        return false;
                return true;
        }

        if (MATCH(data->payload[1], ANY, ANY, 0x00, 0x00) &&
                        data->payload_len[1] != 0) {
                if (data->payload_len[0] != 0)
                        return false;
                return true;
        }


	return false;
}

static lpi_module_t lpi_mp2p_udp = {
	LPI_PROTO_UDP_MP2P,
	LPI_CATEGORY_P2P,
	"MP2P_UDP",
	4,
	match_mp2p_udp
};

void register_mp2p_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_mp2p_udp, mod_map);
}

