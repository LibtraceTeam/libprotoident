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

/* Some Chinese Flash-based FPS game */

static inline bool match_ssjj_3611(uint32_t payload, uint32_t len) {

        /* payload is a length field, but length exceeds typical MTU */
        if (len > 1380 && MATCH(payload, 0x00, 0x00, 0x36, 0x11))
                return true;
        return false;

}

static inline bool match_ssjj_61(uint32_t payload, uint32_t len) {

        /* payload is a length field */
        if (len == 101 && MATCH(payload, 0x00, 0x00, 0x00, 0x61))
                return true;
        return false;

}

static inline bool match_ssjj(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_ssjj_3611(data->payload[0], data->payload_len[0])) {
                if (match_ssjj_61(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_ssjj_3611(data->payload[1], data->payload_len[1])) {
                if (match_ssjj_61(data->payload[0], data->payload_len[0]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_ssjj = {
	LPI_PROTO_SSJJ,
	LPI_CATEGORY_GAMING,
	"SSJJ",
	5,
	match_ssjj
};

void register_ssjj(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ssjj, mod_map);
}

