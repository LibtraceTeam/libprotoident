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

static bool match_length_single(uint32_t payload, uint32_t len) {

        uint32_t statedlen;

        if (len == 2) {
                return true;
        }

        statedlen = (ntohl(payload) >> 16);

        if (statedlen < 1280) {
                if (statedlen != len - 2)
                        return false;
        }

        return true;
}

static bool match_dns_tcp_length(lpi_data_t *data) {

        uint32_t id0, id1;

        if (data->payload_len[0] == 0 || data->payload_len[1] == 0)
                return false;

        if (data->server_port != 53 && data->client_port != 53)
                return false;

        if (!match_length_single(data->payload[0], data->payload_len[0]))
                return false;

        if (!match_length_single(data->payload[1], data->payload_len[1]))
                return false;

        if (data->payload_len[0] > 2 && data->payload_len[1] > 2) {

                id0 = (ntohl(data->payload[0]) & 0xffff);
                id1 = (ntohl(data->payload[1]) & 0xffff);

                if (id0 != id1)
                        return false;
        }


        return true;
}


static bool match_tcp_dns(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_dns(data))
		return true;
	if (match_dns_tcp_length(data))
		return true;
	
	return false;

}

static lpi_module_t lpi_dns = {
	LPI_PROTO_DNS,
	LPI_CATEGORY_SERVICES,
	"DNS_TCP",
	6, 	/* Not a high certainty */
	match_tcp_dns
};

void register_dns_tcp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_dns, mod_map);
}
