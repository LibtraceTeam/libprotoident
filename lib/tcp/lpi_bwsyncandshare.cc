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

/* Have not tested against the application itself, as it is restricted
 * to certain German universities. There may be more variants of this
 * traffic.
 */

static inline bool match_bws_951(uint32_t payload, uint32_t len) {
        if (len == 4 && MATCH(payload, 0x00, 0x00, 0x09, 0x51))
                return true;
        return false;
}

static inline bool match_bws_other(uint32_t payload, uint32_t len) {

        uint32_t lastbyte = ntohl(payload) & 0x000000ff;

        if (len == 4 && MATCH(payload, 0x00, 0x00, 0x08, ANY)) {
                /* Byte 4 is always 0xfX, where X can be just about
                 * anything.
                 */
                if ((lastbyte & 0xf0) == 0xf0)
                        return true;
        }
        return false;
}

static inline bool match_bwsyncandshare(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Port 60107? */
        if (match_bws_951(data->payload[0], data->payload_len[0])) {
                if (match_bws_other(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_bws_951(data->payload[1], data->payload_len[1])) {
                if (match_bws_other(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_bwsyncandshare = {
	LPI_PROTO_BWSYNC,
	LPI_CATEGORY_CLOUD,
	"BWSyncAndShare",
	120,
	match_bwsyncandshare
};

void register_bwsyncandshare(LPIModuleMap *mod_map) {
	register_protocol(&lpi_bwsyncandshare, mod_map);
}

