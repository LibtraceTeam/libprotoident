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

static inline bool match_360_a1req(uint32_t payload, uint32_t len) {

        if (len != 63)
                return false;
        if (MATCH(payload, 0xa1, 0x00, 0x00, 0x00))
                return true;
        return false;

}

static inline bool match_360_a1resp(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0xa1, 0x82, 0x00, 0x00))
                return true;
        return false;

}

static inline bool match_360_03req(uint32_t payload, uint32_t len) {

        uint32_t hdrlen = (ntohl(payload) & 0xffff);

        if (!MATCH(payload, 0x00, 0x03, 0x00, ANY))
                return false;
        if (len - 8 == hdrlen)
                return true;
        return false;

}

static inline bool match_360_03resp(uint32_t payload, uint32_t len) {

        if (len != 8)
                return false;
        if (MATCH(payload, 0x00, 0x00, 0x00, 0x00))
                return true;
        return false;

}

static inline bool match_360safeguard(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* These patterns have been regularly seen on a machine with 360
         * safeguard (Chinese edition) installed. They seem to appear when 
         * starting up and running a scan, so are probably some form of update
         * checking?
         */

        if (match_360_a1req(data->payload[0], data->payload_len[0])) {
                if (match_360_a1resp(data->payload[1], data->payload_len[1]))
                        return true;
        }
        
        if (match_360_a1req(data->payload[1], data->payload_len[1])) {
                if (match_360_a1resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_360_03req(data->payload[0], data->payload_len[0])) {
                if (match_360_03resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_360_03req(data->payload[1], data->payload_len[1])) {
                if (match_360_03resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_360safeguard = {
	LPI_PROTO_360SAFEGUARD,
	LPI_CATEGORY_SECURITY,
	"360Safeguard",
	8,
	match_360safeguard
};

void register_360safeguard(LPIModuleMap *mod_map) {
	register_protocol(&lpi_360safeguard, mod_map);
}

