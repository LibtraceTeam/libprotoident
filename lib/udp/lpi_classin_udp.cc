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

static inline bool match_classin_41(uint32_t payload, uint32_t len) {
        if (len == 41 && MATCH(payload, 0x1a, 0x03, 0x00, 0x02)) {
                return true;
        }
        return false;
}

static inline bool match_classin_56(uint32_t payload, uint32_t len) {
        if (len == 56 && MATCH(payload, 0x1a, 0x03, 0x00, 0x02)) {
                return true;
        }
        return false;
}

static inline bool match_classin_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_classin_41(data->payload[0], data->payload_len[0])) {
                if (match_classin_56(data->payload[1], data->payload_len[1])) {
                        return true;
                }
        }

        if (match_classin_41(data->payload[1], data->payload_len[1])) {
                if (match_classin_56(data->payload[0], data->payload_len[0])) {
                        return true;
                }
        }

	return false;
}

static lpi_module_t lpi_classin_udp = {
	LPI_PROTO_UDP_CLASSIN,
	LPI_CATEGORY_EDUCATIONAL,
	"ClassIn_UDP",
	133,
	match_classin_udp
};

void register_classin_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_classin_udp, mod_map);
}

