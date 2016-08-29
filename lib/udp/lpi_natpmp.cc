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

static inline bool match_natpmp_probe(uint32_t payload, uint32_t len) {
        if (len != 2)
                return false;

        if (!MATCHSTR(payload, "\x00\x00\x00\x00"))
                return false;

        return true;

}

static inline bool match_natpmp_response(uint32_t payload, uint32_t len) {
        if (len == 0)
                return true;

        /* Just guessing based on RFC6886 */
        if (len != 12)
                return false;

        if (!MATCHSTR(payload, "\x00\x80\x00\x00"))
                return false;

        return true;

}

static inline bool match_natpmp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* XXX Shall we limit to port 5351 only? */

        /* Only seen attempted scanning so far */
        if (match_natpmp_probe(data->payload[0], data->payload_len[0])) {
                if (match_natpmp_response(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_natpmp_probe(data->payload[1], data->payload_len[1])) {
                if (match_natpmp_response(data->payload[0], data->payload_len[0]))
                        return true;
        }
	return false;
}

static lpi_module_t lpi_natpmp = {
	LPI_PROTO_UDP_NATPMP,
	LPI_CATEGORY_NAT,
	"NAT-PMP",
	20,
	match_natpmp
};

void register_natpmp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_natpmp, mod_map);
}

