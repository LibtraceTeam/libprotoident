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

/* Chinese VPN for accessing mainland content */

static inline bool match_ts_23(uint32_t payload, uint32_t len) {

        if (len == 23 && MATCH(payload, 0x00, 0x00, 0x00, 0x00)) {
                return true;
        }

        return false;
}

static inline bool match_ts_reply(uint32_t payload, uint32_t len) {

        /* Payload is random, but we could add rules to return false
         * if the payload is 00000000 or ffffffff (or any other clearly
         * intentional pattern), if this is generating FPs.
         */

        /* Lower path MTUs would affect this number, but let's concentrate
         * on getting the lowest hanging fruit for now.
         */
        if (len == 1460) {
                return true;
        }
        return false;

}

static inline bool match_transocks(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_ts_23(data->payload[0], data->payload_len[0])) {
                if (match_ts_reply(data->payload[1], data->payload_len[1])) {
                        return true;
                }
        }

        if (match_ts_23(data->payload[0], data->payload_len[0])) {
                if (match_ts_reply(data->payload[1], data->payload_len[1])) {
                        return true;
                }
        }

	return false;
}

static lpi_module_t lpi_transocks = {
	LPI_PROTO_TRANSOCKS,
	LPI_CATEGORY_TUNNELLING,
	"Transocks",
	240,
	match_transocks
};

void register_transocks(LPIModuleMap *mod_map) {
	register_protocol(&lpi_transocks, mod_map);
}

