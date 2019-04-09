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

static inline bool match_line_108(uint32_t payload, uint32_t len) {

        if (len != 108)
                return false;
        if (MATCH(payload, 0xb6, 0x12, 0x00, 0x68))
                return true;
        return false;

}

static inline bool match_line_110(uint32_t payload, uint32_t len) {

        if (len != 110)
                return false;
        if (MATCH(payload, 0xb6, 0x18, 0x00, 0x6a))
                return true;
        return false;

}

static inline bool match_line_35(uint32_t payload, uint32_t len) {

        if (!MATCH(payload, 0xb6, 0x13, 0x00, 0x06))
                return false;
        if (len == 35 || len == 46)
                return true;
        return false;

}

static inline bool match_line_16(uint32_t payload, uint32_t len) {
        if (len == 0)
                return true;

        if (len == 16 && MATCH(payload, 0xb6, 0x09, 0x00, 0x0c))
                return true;

        return false;
}

static inline bool match_line_43(uint32_t payload, uint32_t len) {

        if (len == 43 && MATCH(payload, 0xb6, 0x13, 0x00, 0x27))
                return true;
        if (len == 43 && MATCH(payload, 0xb6, 0x14, 0x00, 0x27))
                return true;
        return false;

}

static inline bool match_line_46(uint32_t payload, uint32_t len) {

        if (len == 46 && MATCH(payload, 0xb6, 0x15, 0x00, 0x06))
                return true;
        return false;

}

static inline bool match_line_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_line_108(data->payload[0], data->payload_len[0])) {
                if (match_line_35(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_line_108(data->payload[1], data->payload_len[1])) {
                if (match_line_35(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_line_110(data->payload[0], data->payload_len[0])) {
                if (match_line_35(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_line_110(data->payload[1], data->payload_len[1])) {
                if (match_line_35(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_line_43(data->payload[0], data->payload_len[0])) {
                if (match_line_46(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_line_43(data->payload[1], data->payload_len[1])) {
                if (match_line_46(data->payload[0], data->payload_len[0]))
                        return true;
        }

        /* Not 100% sure about this one, but the few clues I have make me
         * think this is likely to be Line.
         *   1. all connections use at least one port in the 50000+ range.
         *   2. many remote addresses are in Japanese ASNs.
         *   3. first byte of payload is 0xb6.
         */
        if (match_line_16(data->payload[0], data->payload_len[0])) {
                if (match_line_16(data->payload[1], data->payload_len[1]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_line_udp = {
	LPI_PROTO_UDP_LINE,
	LPI_CATEGORY_CHAT,
	"Line_UDP",
	16,
	match_line_udp
};

void register_line_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_line_udp, mod_map);
}

