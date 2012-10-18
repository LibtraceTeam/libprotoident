/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011 The University of Waikato, Hamilton, New Zealand.
 * Author: Shane Alcock
 *
 * With contributions from:
 *      Aaron Murrihy
 *      Donald Neal
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libprotoident; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: lpi_spotify.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_spotify_02_req(uint32_t payload, uint32_t len) {
	uint32_t len_field = 0;

	/* Type 0x02 has a 16 bit length field */

	/* The 0x01 is part of the length too... */
	if (!MATCH(payload, 0x00, 0x02, 0x01, ANY))
		return false;
	
	/* The last byte is the length of the packet - 256 */
	len_field = (ntohl(payload)) & 0xff;

	if (len_field == len - 256)
		return true;
	return false;

}

static inline bool match_spotify_04_req(uint32_t payload, uint32_t len) {

	if (!MATCH(payload, 0x00, 0x04, 0x00, 0x00))
		return false;

	return true;
}


static inline bool match_spotify_02_resp(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
	if (len < 512)
		return false;
	if (!MATCH(payload, 0x00, ANY, ANY, ANY))
		return false;
	return true;
}

static inline bool match_spotify_04_resp(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
	if (ntohl(payload) != len)
		return false;
	return true;

}

static inline bool match_spotify(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Make sure we're using the right port */
	if (data->server_port != 4070 && data->client_port != 4070) {
		/* Port 443 is used for uploading? */
		if (data->server_port != 443 && data->client_port != 443)
			return false;
	}

	if (match_spotify_02_req(data->payload[0], data->payload_len[0])) {
		if (match_spotify_02_resp(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_spotify_02_req(data->payload[1], data->payload_len[1])) {
		if (match_spotify_02_resp(data->payload[0], data->payload_len[0]))
			return true;
	}
	
	if (match_spotify_04_req(data->payload[0], data->payload_len[0])) {
		if (match_spotify_04_resp(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_spotify_04_req(data->payload[1], data->payload_len[1])) {
		if (match_spotify_04_resp(data->payload[0], data->payload_len[0]))
			return true;
	}
	return false;
}

static lpi_module_t lpi_spotify = {
	LPI_PROTO_SPOTIFY,
	LPI_CATEGORY_STREAMING,
	"Spotify",
	7,
	match_spotify
};

void register_spotify(LPIModuleMap *mod_map) {
	register_protocol(&lpi_spotify, mod_map);
}

