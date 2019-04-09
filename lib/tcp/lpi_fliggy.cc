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


/* Bytes 3 and 4 are a length field */
static inline bool match_fliggy_req(uint32_t payload, uint32_t len) {

        uint32_t hlen = ntohl(payload) & 0xffff;

        if (MATCH(payload, 0xd1, 0x00, ANY, ANY) ||
                        MATCH(payload, 0xd5, 0x00, ANY, ANY)) {
                if (hlen == len - 4)
                        return true;
                /* Try to account for messages that are longer than one MTU */
                if (len >= 1300 && hlen > len)
                        return true;
        }

        if (MATCH(payload, 0xd5, 0x00, 0x01, 0x16) && len >= 282) {
                return true;
        }
        return false;
}

static inline bool match_fliggy_resp(uint32_t payload, uint32_t len) {

        /* Usually, but not always 174 bytes -- I'm guessing sometimes
         * messages get merged?
         */
        if (MATCH(payload, 0xd3, 0x00, 0x00, 0xaa) && len >= 174)
                return true;

        /* Same for this one, usually 58 but not always */
        if (MATCH(payload, 0xd3, 0x00, 0x00, 0x36) && len >= 58)
                return true;
        return false;

}

static inline bool match_fliggy(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Ports 80 and 443, typically */

        if (match_fliggy_req(data->payload[0], data->payload_len[0])) {
                if (match_fliggy_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_fliggy_req(data->payload[1], data->payload_len[1])) {
                if (match_fliggy_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_fliggy = {
	LPI_PROTO_FLIGGY,
	LPI_CATEGORY_ECOMMERCE,
	"Fliggy",
	30,
	match_fliggy
};

void register_fliggy(LPIModuleMap *mod_map) {
	register_protocol(&lpi_fliggy, mod_map);
}

