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

static inline bool match_rtmp_server_handshake(uint32_t payload, uint32_t len,
                bool defaultport) {

	if (len < 4 && !defaultport)
		return false;

	/* Standard RTMP handshake types */	
	if (MATCH(payload, 0x03, ANY, ANY, ANY))
		return true;
	if (MATCH(payload, 0x06, ANY, ANY, ANY))
		return true;

	/* Encrypted, but not RTMPE? */
	if (MATCH(payload, 0x08, ANY, ANY, ANY))
		return true;


	/* RTMPE handshake type */
	if (MATCH(payload, 0x09, ANY, ANY, ANY))
		return true;

	/* New handshake type used by some YouTube videos */
	if (MATCH(payload, 0x0a, ANY, ANY, ANY))
		return true;

	return false;
}

static inline bool match_rtmp_client_handshake(uint32_t payload, uint32_t len) {

	if (len < 4)
		return false;

	/* Standard RTMP handshake types */	
	if (MATCH(payload, 0x03, ANY, ANY, ANY))
		return true;
	if (MATCH(payload, 0x06, ANY, ANY, ANY))
		return true;

	return false;
}

static inline bool match_rtmp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        bool defaultport = false;

        if (data->server_port == 1935 || data->client_port == 1935)
                defaultport = true;

	if (match_rtmp_client_handshake(data->payload[0], data->payload_len[0]))
	{
		if (match_rtmp_server_handshake(data->payload[1], 
				data->payload_len[1], defaultport)) {
			return true;
		}
	}

	if (match_rtmp_client_handshake(data->payload[1], data->payload_len[1]))
	{
		if (match_rtmp_server_handshake(data->payload[0], 
				data->payload_len[0], defaultport)) {
			return true;
		}
	}
	return false;
}

static lpi_module_t lpi_rtmp = {
	LPI_PROTO_RTMP,
	LPI_CATEGORY_STREAMING,
	"RTMP",
	16,	/* Not a strong rule */
	match_rtmp
};

void register_rtmp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_rtmp, mod_map);
}

