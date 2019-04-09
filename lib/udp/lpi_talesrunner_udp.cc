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

static inline bool match_tr_1b(uint32_t payload, uint32_t len) {
        if (len == 8 && MATCH(payload, 0x1b, 0x00, 0xb2, 0x1a))
                return true;
        return false;
}

static inline bool match_tr_1e(uint32_t payload, uint32_t len) {
        if (len == 8 && MATCH(payload, 0x1e, 0x00, 0x6b, 0x51))
                return true;
        return false;
}

static inline bool match_talesrunner_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (MATCH(data->payload[0], 0x1d, 0x00, 0x67, 0x01)) {
                if (MATCH(data->payload[1], 0x1d, 0x00, 0x61, 0x01)) {

                        /* One of the packets is always 8 bytes */
                        if (data->payload_len[0] == 8 ||
                                        data->payload_len[1] == 8) {
                                return true;
                        }
                }
        }

        if (match_tr_1b(data->payload[0], data->payload_len[0])) {
                if (match_tr_1b(data->payload[1], data->payload_len[1]))
                        return true;
        }


        if (match_tr_1e(data->payload[0], data->payload_len[0])) {
                if (match_tr_1e(data->payload[1], data->payload_len[1]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_talesrunner_udp = {
	LPI_PROTO_UDP_TALESRUNNER,
	LPI_CATEGORY_GAMING,
	"TalesrunnerUDP",
	59,
	match_talesrunner_udp
};

void register_talesrunner_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_talesrunner_udp, mod_map);
}

