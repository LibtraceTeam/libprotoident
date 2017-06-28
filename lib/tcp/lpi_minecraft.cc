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

static inline bool match_mc_server_ping(uint32_t payload, uint32_t len) {

	/* There are two variants of the server ping
	 *
	 * http://mc.kev009.com/Server_List_Ping
	 */

	if (len == 1) {
		if (MATCH(payload, 0xfe, 0x00, 0x00, 0x00))
			return true;
	}

	if (len == 2) {
		if (MATCH(payload, 0xf3, 0x01, 0x00, 0x00))
			return true;
	}

	return false;

}

static inline bool match_mc_kick(uint32_t payload, uint32_t len) {

	uint32_t str_len;

	if (!MATCH(payload, 0xff, ANY, ANY, 0x00))
		return false;

	/* Middle 2 bytes are the length of the string following the initial
	 * header. Unfortunately there is more to the packet after the string,
	 * so we just have to check that the length makes sense given the size
	 * of the packet */

	str_len = (ntohl(payload) >> 8) & 0xffff;

	if (str_len >= len)
		return false;
	return true;

}

static inline bool match_mc_handshake(uint32_t payload, uint32_t len) {
        /* Ref: http://wiki.vg/Protocol */
        uint32_t replen;

        replen = ntohl(payload) >> 24;

        if (replen == len - 1) {
                if (MATCH(payload, ANY, 0x00, ANY, ANY) && len - 1 <= 255)
                        return true;
                if (MATCH(payload, ANY, 0x01, ANY, ANY) && len - 1 >= 256)
                        return true;
        }

        /* Some handshakes seem to be undersized? */
        if (len == 189 && MATCH(payload, 0xbb, 0x01, 0x01, 0x10))
                return true;
        if (len == 190 && MATCH(payload, 0xbc, 0x01, 0x01, 0x11))
                return true;

        return false;
}

static inline bool match_mc_handshake_reply(uint32_t payload, uint32_t len) {

        /* Not technically a handshake reply, as the protocol spec doesn't
         * have one. This pattern is what we see in the other direction
         * after a handshake though.
         */
        if (len == 173) {
                if (MATCH(payload, 0xab, 0x01, 0x01, 0x00))
                        return true;
        }

        if (len == 4) {
                if (MATCH(payload, 0x03, 0x03, 0x80, 0x02))
                        return true;
        }

        return false;

}

static inline bool match_minecraft(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_mc_server_ping(data->payload[0], data->payload_len[0])) {
		if (match_mc_kick(data->payload[1], data->payload_len[1])) {
			return true;
		}
	}

	if (match_mc_server_ping(data->payload[1], data->payload_len[1])) {
		if (match_mc_kick(data->payload[0], data->payload_len[0])) {
			return true;
		}
	}

        if (match_mc_handshake(data->payload[0], data->payload_len[0])) {
                if (match_mc_handshake_reply(data->payload[1],
                                data->payload_len[1]))
                        return true;
        }

        if (match_mc_handshake(data->payload[1], data->payload_len[1])) {
                if (match_mc_handshake_reply(data->payload[0],
                                data->payload_len[0]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_minecraft = {
	LPI_PROTO_MINECRAFT,
	LPI_CATEGORY_GAMING,
	"Minecraft",
	35,
	match_minecraft
};

void register_minecraft(LPIModuleMap *mod_map) {
	register_protocol(&lpi_minecraft, mod_map);
}

