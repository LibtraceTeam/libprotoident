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

/* More specifically, this rule is based off Rising Storm 2 but it'll
 * probably match other Tripwire games including the original.
 *
 * TBC against real game traffic, but that costs $$.
 * All servers contacted were labelled as RS2 on various server tracking
 * sites, so that's enough for me.
 */

static inline bool match_rs_0080(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x00, 0x80, 0x05, 0x20)) {
                if (len == 10 || len == 17)
                        return true;
        }
        return false;

}

static inline bool match_rs_00c0(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x00, 0xc0, ANY, 0x08)) {
                if (len == 14)
                        return true;
        }
        return false;
}

static inline bool match_rs_0108(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x00, 0x00, 0x01, 0x08)) {
                if (len == 25 || len == 12)
                        return true;
        }
        return false;
}

static inline bool match_risingstorm(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_rs_0080(data->payload[0], data->payload_len[0])) {
                if (match_rs_0108(data->payload[1], data->payload_len[1]))
                        return true;

                if (match_rs_00c0(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_rs_0080(data->payload[1], data->payload_len[1])) {
                if (match_rs_0108(data->payload[0], data->payload_len[0]))
                        return true;

                if (match_rs_00c0(data->payload[0], data->payload_len[0]))
                        return true;
        }



	return false;
}

static lpi_module_t lpi_risingstorm = {
	LPI_PROTO_UDP_RISING_STORM,
	LPI_CATEGORY_GAMING,
	"RisingStorm",
	12,
	match_risingstorm
};

void register_risingstorm(LPIModuleMap *mod_map) {
	register_protocol(&lpi_risingstorm, mod_map);
}

