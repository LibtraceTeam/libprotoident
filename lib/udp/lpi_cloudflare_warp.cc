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

/* 01 == handshake begin */
static inline bool match_warp_01(uint32_t payload, uint32_t len) {

        if (len != 148) {
                return false;
        }

        if (MATCH(payload, 0x01, ANY, ANY, ANY)) {
                if (MATCH(payload, 0x01, 0x00, 0x00, 0x00)) {
                        return false;
                }
                return true;
        }
        return false;
}

/* 02 == handshake reply */
static inline bool match_warp_02(uint32_t payload, uint32_t len) {

        if (len != 92) {
                return false;
        }

        if (MATCH(payload, 0x02, ANY, ANY, ANY)) {
                return true;
        }
        return false;
}

/* 04 == data (for sessions where we missed part of the handshake */
static inline bool match_warp_04(uint32_t payload, uint32_t len) {

        /* 100 is approximate, but 1312 seems to be an actual
         * Max Datagram Size */
        if (len < 100 || len > 1312) {
                return false;
        }

        if (MATCH(payload, 0x04, ANY, ANY, ANY)) {
                return true;
        }
        return false;
}

static inline bool is_cf_warp_port(lpi_data_t *data) {
        if (data->server_port == 2408 || data->client_port == 2408) {
                return true;
        }
        if (data->server_port == 1701 || data->client_port == 1701) {
                return true;
        }
        if (data->server_port == 500 || data->client_port == 500) {
                return true;
        }
        return false;
}


static inline bool match_cloudflare_warp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (!is_cf_warp_port(data)) {
                return false;
        }

        if (match_warp_01(data->payload[0], data->payload_len[0])) {
                if (match_warp_02(data->payload[1], data->payload_len[1])) {
                        return true;
                }
                if (match_warp_04(data->payload[1], data->payload_len[1])) {
                        return true;
                }
        }

        if (match_warp_01(data->payload[1], data->payload_len[1])) {
                if (match_warp_02(data->payload[0], data->payload_len[0])) {
                        return true;
                }
                if (match_warp_04(data->payload[0], data->payload_len[0])) {
                        return true;
                }
        }

	return false;
}

static lpi_module_t lpi_cloudflare_warp = {
	LPI_PROTO_UDP_CLOUDFLARE_WARP,
	LPI_CATEGORY_TUNNELLING,
	"CloudflareWarp",
	21,
	match_cloudflare_warp
};

void register_cloudflare_warp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_cloudflare_warp, mod_map);
}

