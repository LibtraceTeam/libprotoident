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

/* Virtual world a la Second Life, but even more targeted towards virtual sex */

static inline bool match_uther_21(uint32_t payload, uint32_t len) {
        if (len == 21 && MATCH(payload, 0x11, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_uther_other(uint32_t payload, uint32_t len) {

        /* It's a length field, but in little endian */
        /* Max length appears to be hard-coded to 1350 */

        if (len > 1350) {
                return false;
        } else if (len == 1350) {
                if (MATCH(payload, ANY, ANY, 0x00, 0x00)) {
                        if (!MATCH(payload, ANY, 0x00, 0x00, 0x00))
                                return true;
                }
        } else {
                if (bswap_le_to_host32(payload) == len + 4) {
                        return true;
                }
        }

        return false;
}

static inline bool match_utherverse(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->server_port != 4991 && data->client_port != 4991) {
                return false;
        }

        if (match_uther_21(data->payload[0], data->payload_len[0])) {
                if (match_uther_other(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_uther_21(data->payload[1], data->payload_len[1])) {
                if (match_uther_other(data->payload[0], data->payload_len[0]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_utherverse = {
	LPI_PROTO_UTHERVERSE,
	LPI_CATEGORY_GAMING,
	"Utherverse",
	200,
	match_utherverse
};

void register_utherverse(LPIModuleMap *mod_map) {
	register_protocol(&lpi_utherverse, mod_map);
}

