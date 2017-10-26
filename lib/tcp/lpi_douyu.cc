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

/* This is a classic 4-byte length protocol, but there is plenty of
 * scope for the packet sizes to vary a bit so we can't just look for
 * a specific combo of packet sizes */

static inline bool match_douyu_req(uint32_t payload, uint32_t len) {

        uint32_t plen = bswap_le_to_host32(payload);

        /* Packet usually contains a username and a password so
         * can probably vary quite a bit in size */
        if (plen == len - 4) {
                if (len <= 255)
                        return true;
        }

        return false;
}

static inline bool match_douyu_reply(uint32_t payload, uint32_t len) {

        uint32_t plen = bswap_le_to_host32(payload);

        /* Response packets seem like they will vary a lot less in
         * size -- could be wrong though */

        if (plen == len - 4) {
                if (len >= 225 && len <= 255)
                        return true;
        }

        return false;
}

static inline bool match_douyu_port(uint16_t port) {

        /* Based purely on observed flows, rather than any docs */
        if (port >= 8601 && port <= 8605)
                return true;
        if (port >= 12601 && port <= 12605)
                return true;
        return false;
}

static inline bool match_douyu(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Tends to use a couple of different port ranges */
        if (!match_douyu_port(data->server_port) && 
                        !match_douyu_port(data->client_port)) {
                return false;
        }

        if (match_douyu_req(data->payload[0], data->payload_len[0])) {
                if (match_douyu_reply(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_douyu_req(data->payload[1], data->payload_len[1])) {
                if (match_douyu_reply(data->payload[0], data->payload_len[0]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_douyu = {
	LPI_PROTO_DOUYU,
	LPI_CATEGORY_STREAMING,
	"Douyu",
	249,
	match_douyu
};

void register_douyu(LPIModuleMap *mod_map) {
	register_protocol(&lpi_douyu, mod_map);
}

