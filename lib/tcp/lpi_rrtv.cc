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

/* rr.tv -- P2P TV/video streaming from China */

/* XXX mobile only, need to test the app properly but the initial
 * packets literally include URLs referring to rr.tv so I'm pretty
 * confident.
 */

static inline bool match_rrtv_header(uint32_t payload, uint32_t len) {

        /* broad estimate based on what I've seen so far */
        if (len < 550 || len > 700) {
                return false;
        }

        if ((ntohl(payload) & 0x0000ffff) != len - 4) {
                return false;
        }

        if (MATCH(payload, 0x01, 0x10, ANY, ANY)) {
                return true;
        }

        return false;
}

static inline bool match_rrtv(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_rrtv_header(data->payload[0], data->payload_len[0])) {
                if (match_rrtv_header(data->payload[1], data->payload_len[1])) {
                        return true;
                }
        }

	return false;
}

static lpi_module_t lpi_rrtv = {
	LPI_PROTO_RRTV,
	LPI_CATEGORY_P2PTV,
	"RR.tv",
	120,
	match_rrtv
};

void register_rrtv(LPIModuleMap *mod_map) {
	register_protocol(&lpi_rrtv, mod_map);
}

