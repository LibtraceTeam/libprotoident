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

static inline bool match_vivox_request(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x80, 0x7f, 0x00, 0x00) && len == 112)
                return true;
        return false;

}

static inline bool match_vivox_reply(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x80, 0x7f, 0x00, 0x00) && len == 99)
                return true;
        return false;

}

static inline bool match_vivox_stun(uint32_t payload, uint32_t len) {

        /* Vivox mixes a whole bunch of RTP(?) and STUN together
         * when it starts up, so sometimes the STUN replies arrive
         * first. */
        if (MATCH(payload, 0x01, 0x01, 0x00, 0x70) && len == 132)
                return true;
        return false;

}

static inline bool match_vivox(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_vivox_request(data->payload[0], data->payload_len[0])) {
                if (match_vivox_stun(data->payload[1], data->payload_len[1]))
                        return true;
                if (match_vivox_reply(data->payload[1], data->payload_len[1]))
                        return true;
        }
        if (match_vivox_request(data->payload[1], data->payload_len[1])) {
                if (match_vivox_stun(data->payload[0], data->payload_len[0]))
                        return true;
                if (match_vivox_reply(data->payload[0], data->payload_len[0]))
                        return true;
        }

	/* Seen this to Vivox servers, so I'm going to make the logical
         * assumption */
        if (!match_str_both(data, "\x80\x6f\x00\x00", "\x80\x6f\x00\x01"))
                return false;

        if (data->payload_len[0] == 108 || data->payload_len[1] == 108)
                return true;

	return false;
}

static lpi_module_t lpi_vivox = {
	LPI_PROTO_UDP_VIVOX,
	LPI_CATEGORY_VOIP,
	"Vivox",
	5,
	match_vivox
};

void register_vivox(LPIModuleMap *mod_map) {
	register_protocol(&lpi_vivox, mod_map);
}

