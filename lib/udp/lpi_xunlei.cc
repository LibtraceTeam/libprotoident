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

static inline bool xunlei_32(uint32_t payload, uint32_t len) {
	if (len == 0)
		return true;

	if (!MATCH(payload, 0x32, 0x00, 0x00, 0x00))
		return false;

	if (len == 29)
		return true;
	if (len == 31)
		return true;
	return false;
}

static inline bool match_shuijing_3b_other(uint32_t payload, uint32_t len) {
        if (!MATCH(payload, 0x3b, 0x00, 0x00, 0x00))
                return false;
	if (len == 31 || len == 29 || len == 42)
		return true;
        return false;
}

static inline bool match_shuijing_32(uint32_t payload, uint32_t len) {
        if (len == 31 && MATCH(payload, 0x32, 0x00, 0x00, 0x00))
                return true;
        if (len == 29 && MATCH(payload, 0x32, 0x00, 0x00, 0x00))
                return true;
        if (len == 42 && MATCH(payload, 0x32, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_shuijing_3b(uint32_t payload, uint32_t len) {
        if (len == 33 && MATCH(payload, 0x3b, 0x00, 0x00, 0x00))
                return true;
        if (len == 31 && MATCH(payload, 0x3b, 0x00, 0x00, 0x00))
                return true;
        if (len == 29 && MATCH(payload, 0x3b, 0x00, 0x00, 0x00))
                return true;
        if (len == 13 && MATCH(payload, 0x3b, 0x00, 0x00, 0x00))
                return true;
        return false;
}


static inline bool match_xunlei_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Shuijing = "Thunder Crystal", a P2P CDN approach used by Xunlei.
         * Uses UDP port 4693 normally */

        if (match_shuijing_3b(data->payload[0], data->payload_len[0])) {
                if (match_shuijing_3b_other(data->payload[1], data->payload_len[1]))
                        return true;
                if (match_shuijing_32(data->payload[1], data->payload_len[1]))
                        return true;

        }
        
        if (match_shuijing_3b(data->payload[1], data->payload_len[1])) {
                if (match_shuijing_3b_other(data->payload[0], data->payload_len[0]))
                        return true;
                if (match_shuijing_32(data->payload[0], data->payload_len[0]))
                        return true;
        }


        /* Traffic seen while operating the Thunder client, not sure on exact
         * purpose but can lead to large flows. Rule is not very strong, since
         * the payload seems random.
         */
        if (data->server_port == 12345 || data->client_port == 12345) {
                if (data->payload[0] != 0 && data->payload[1] != 0) {
                        if (data->payload_len[0] >= 39) {
                                if (data->payload_len[0] <= 43) {
                                        if (data->payload_len[1] >= 39) {
                                                if (data->payload_len[1] <= 43)
                                                        return true;
                                        }
                                }
                        }
                }
        }

        if (match_str_both(data, "\x32\x00\x00\x00", "\x32\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x36\x00\x00\x00", "\x36\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x35\x00\x00\x00", "\x35\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x35\x00\x00\x00", "\x28\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x35\x00\x00\x00", "\x29\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x34\x00\x00\x00", "\x34\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x34\x00\x00\x00", "\x29\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x33\x00\x00\x00", "\x33\x00\x00\x00"))
                return true;

	if (xunlei_32(data->payload[0], data->payload_len[0])) {
		if (xunlei_32(data->payload[1], data->payload_len[1]))
			return true;
	}
	/* Require port 3076 for now, as all these rules are based on
         * traffic seen on port 3076 */
        if (data->server_port != 3076 && data->client_port != 3076)
                return false;

	
        if (match_str_either(data, "\x36\x00\x00\x00")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }
        if (match_str_either(data, "\x35\x00\x00\x00")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }
        if (match_str_either(data, "\x34\x00\x00\x00")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }
        if (match_str_either(data, "\x33\x00\x00\x00")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }
        if (match_str_either(data, "\x29\x00\x00\x00")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }

	return false;
}

static lpi_module_t lpi_xunlei_udp = {
	LPI_PROTO_UDP_XUNLEI,
	LPI_CATEGORY_P2P,
	"Xunlei_UDP",
	203,
	match_xunlei_udp
};

void register_xunlei_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_xunlei_udp, mod_map);
}

