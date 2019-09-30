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

static inline bool match_qvod_1(uint32_t payload, uint32_t len) {

        if (len == 1 && MATCH(payload, 0x30, 0x00, 0x00, 0x00)) {
                return true;
        }
        return false;
}

static inline bool match_qvod_13(uint32_t payload, uint32_t len) {

        if (len == 13 && MATCH(payload, 0x00, 0x00, 0x00, 0x0d)) {
                return true;
        }
        return false;
}

static inline bool match_qvod_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_qvod_13(data->payload[0], data->payload_len[0])) {
                if (match_qvod_13(data->payload[1], data->payload_len[1])) {
                        return true;
                }
        }

        if (match_qvod_1(data->payload[0], data->payload_len[0])) {
                if (match_qvod_13(data->payload[1], data->payload_len[1])) {
                        return true;
                }
        }

        if (match_qvod_1(data->payload[1], data->payload_len[1])) {
                if (match_qvod_13(data->payload[0], data->payload_len[0])) {
                        return true;
                }
        }

	return false;
}

static lpi_module_t lpi_qvod_udp = {
	LPI_PROTO_UDP_QVOD,
	LPI_CATEGORY_P2P,
	"QVOD_UDP",
	201,
	match_qvod_udp
};

void register_qvod_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_qvod_udp, mod_map);
}

