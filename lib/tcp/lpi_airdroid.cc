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

static inline bool match_airdroid_req(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x2a, 0x33, 0x0d, 0x0a)) {
                if (len == 97)
                        return true;
        }

        if (MATCH(payload, 0x2a, 0x35, 0x0d, 0x0a)) {
                if (len == 118 || len == 119)
                        return true;
        }

        return false;
}

static inline bool match_airdroid_resp(uint32_t payload, uint32_t len) {
        if (len != 4)
                return false;
        if (MATCH(payload, 0x2b, 0x68, 0x0d, 0x0a))
                return true;
        return false;
}

static inline bool match_airdroid_get(uint32_t payload) {

        if (MATCH(payload, 'G', 'E', 'T', 0x20))
                return true;
        return false;
}

static inline bool is_hexdigit(uint32_t byte) {

        if (byte < 0x30)
                return false;
        if (byte > 0x39 && byte < 0x61)
                return false;
        if (byte > 0x66)
                return false;
        return true;
}

static inline bool match_airdroid_33(uint32_t payload, uint32_t len) {

        uint32_t ordered = ntohl(payload);
        uint32_t byte;

        /* Needs some proper testing against real airdroid traffic */
        if (len == 33) {
                byte == (ordered & 0xff);
                if (!is_hexdigit(byte))
                        return false;

                byte == ((ordered >> 8) & 0xff);
                if (!is_hexdigit(byte))
                        return false;

                byte == ((ordered >> 16) & 0xff);
                if (!is_hexdigit(byte))
                        return false;

                byte == ((ordered >> 24) & 0xff);
                if (!is_hexdigit(byte))
                        return false;

                return true;
        }
        return false;
}

static inline bool match_airdroid(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_airdroid_req(data->payload[0], data->payload_len[0])) {
                if (match_airdroid_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_airdroid_req(data->payload[1], data->payload_len[1])) {
                if (match_airdroid_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (data->server_port == 9991 || data->client_port == 9991) {
                if (match_airdroid_33(data->payload[0], data->payload_len[0])) {
                        if (match_airdroid_get(data->payload[1]))
                                return true;
                }
                if (match_airdroid_33(data->payload[1], data->payload_len[1])) {
                        if (match_airdroid_get(data->payload[0]))
                                return true;
                }
        }

	return false;
}

static lpi_module_t lpi_airdroid = {
	LPI_PROTO_AIRDROID,
	LPI_CATEGORY_CLOUD,
	"AirDroid",
	12,
	match_airdroid
};

void register_airdroid(LPIModuleMap *mod_map) {
	register_protocol(&lpi_airdroid, mod_map);
}

