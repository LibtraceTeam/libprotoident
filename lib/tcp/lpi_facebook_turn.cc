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

static inline bool match_fbturn_request(uint32_t payload, uint32_t len) {
        /* 0x74 == len - 2, 0x0001 == binding request */

        if (len == 118 && MATCH(payload, 0x00, 0x74, 0x00, 0x01))
                return true;
        if (len == 114 && MATCH(payload, 0x00, 0x70, 0x00, 0x01))
                return true;
        return false;
}

static inline bool match_fbturn_reply(uint32_t payload, uint32_t len) {
        /* 0x40 == len - 2, 0x0101 == binding accepted */

        if (len == 66 && MATCH(payload, 0x00, 0x40, 0x01, 0x01))
                return true;
        return false;
}

static inline bool match_facebook_turn(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Seems to be a slightly custom version of TURN, as there is a two
         * byte length field preceding the conventional STUN header. Can't
         * find any explanation for this in RFC 5766, so maybe it is a Facebook
         * addition?
         */

        if (data->server_port != 443 && data->client_port != 443)
                return false;

        if (match_fbturn_request(data->payload[0], data->payload_len[0])) {
                if (match_fbturn_reply(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_fbturn_request(data->payload[1], data->payload_len[1])) {
                if (match_fbturn_reply(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_facebook_turn = {
	LPI_PROTO_FACEBOOK_TURN,
	LPI_CATEGORY_NAT,
	"FacebookTURN",
	55,
	match_facebook_turn
};

void register_facebook_turn(LPIModuleMap *mod_map) {
	register_protocol(&lpi_facebook_turn, mod_map);
}

