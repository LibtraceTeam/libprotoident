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
 * 255.255.255.255 192.168.10.105 44818 1136 17 1226525494.728 1226525530.720 0 888 00000000 .... 0 63000000 c... 24
 * 192.168.10.105 192.168.10.120 1136 44818 17 1226525494.730 1226525530.722 2775 0 63003300 c.3. 75 00000000 .... 0
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_command(uint32_t payload, uint16_t payload_len) {

        // the second uint16 of the ethernetip header is payload the length
        // but not including the header size of 24 bytes
        uint16_t len = ntohs((uint16_t)ntohl(payload)) + 24;

        if (payload_len != len)
                return false;

	// no op
	if (MATCH(payload, 0x00, 0x00, ANY, ANY))
		return true;
	// list services
	if (MATCH(payload, 0x04, 0x00, ANY, ANY))
		return true;
	// list identity
	if (MATCH(payload, 0x63, 0x00, ANY, ANY))
		return true;
	// list interfaces
	if (MATCH(payload, 0x64, 0x00, ANY, ANY))
		return true;
	// register session
	if (MATCH(payload, 0x65, 0x00, 0x04, 0x00))
		return true;
	// un-register session
	if (MATCH(payload, 0x66, 0x00, ANY, ANY))
		return true;
	// sendrrdata
	if (MATCH(payload, 0x6f, 0x00, ANY, ANY))
		return true;
	// send unit data
	if (MATCH(payload, 0x70, 0x00, ANY, ANY))
		return true;
	// indicate status
	if (MATCH(payload, 0x72, 0x00, ANY, ANY))
		return true;
	// cancel
	if (MATCH(payload, 0x73, 0x00, ANY, ANY))
		return true;
	// error
	if (MATCH(payload, 0xff, 0xff, ANY, ANY))
		return true;

	return false;
}

static inline bool match_ethernetip_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->server_port != 44818 && data->client_port != 44818)
		return false;

	if (match_command(data->payload[0], data->payload_len[0]) ||
            match_command(data->payload[1], data->payload_len[1]))
		return true;

	return false;
}

static lpi_module_t lpi_ethernetip_udp = {
	LPI_PROTO_UDP_ETHERNETIP,
	LPI_CATEGORY_ICS,
	"EtherNet/IP_UDP",
	100,
	match_ethernetip_udp
};

void register_ethernetip_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ethernetip_udp, mod_map);
}
