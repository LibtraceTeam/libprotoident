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

/* MMORPG from the people behind "Funtown" */

static inline bool match_0e01(uint32_t payload, uint32_t len) {

        if (len == 5 && MATCH(payload, 0x05, 0x00, 0x0e, 0x01))
                return true;
        return false;
}

static inline bool match_0f(uint32_t payload, uint32_t len) {

        /* Bytes 1 and 2 are a length field, but length seems to
         * correlate strongly with the value of byte 4 */

        if (len == 64 && MATCH(payload, 0x40, 0x00, 0x0f, 0x0b))
                return true;
        if (len == 61 && MATCH(payload, 0x3d, 0x00, 0x0f, 0x08))
                return true;
        if (len == 61 && MATCH(payload, 0x3c, 0x00, 0x0f, 0x07))
                return true;
        return false;
}

static inline bool match_talesrunner(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* port 9153 */

        if (match_0e01(data->payload[0], data->payload_len[0])) {
                if (match_0f(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_0e01(data->payload[1], data->payload_len[1])) {
                if (match_0f(data->payload[0], data->payload_len[0]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_talesrunner = {
	LPI_PROTO_TALESRUNNER,
	LPI_CATEGORY_GAMING,
	"TalesRunner",
	51,
	match_talesrunner
};

void register_talesrunner(LPIModuleMap *mod_map) {
	register_protocol(&lpi_talesrunner, mod_map);
}

