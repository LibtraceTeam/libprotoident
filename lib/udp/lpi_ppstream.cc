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
#include <stdio.h>

static inline bool ppstream_pattern(uint32_t payload) {

	if (MATCH(payload, ANY, ANY, 0x43, 0x00))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x22))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x23))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x32))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x46))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x47))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x49))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x4c))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x4d))
		return true;
	if (MATCH(payload, ANY, ANY, 0x44, 0x73))
		return true;
	if (MATCH(payload, ANY, ANY, 0x44, 0xb2))
		return true;
	if (MATCH(payload, ANY, ANY, 0x44, 0xb5))
		return true;
	if (MATCH(payload, ANY, ANY, 0x55, 0x72))
		return true;
	if (MATCH(payload, ANY, ANY, 0x55, 0x75))
		return true;
	if (MATCH(payload, ANY, ANY, 0x55, 0xb3))
		return true;

	return false;

}

static inline bool match_ppstream_payload(uint32_t payload, uint32_t len) {
        uint16_t rep_len = 0;
	uint32_t swap = ntohl(payload);

        if (len == 0)
                return true;

	/* Seems to be used on start-up to check access to certain
	 * servers owned by PPStream */
	if (MATCH(payload, 'e', 'c', 'h', 'o') && len == 5)
		return true;

        if (!ppstream_pattern(payload)) 
                return false;

        /* First two bytes are either len or len - 4 */

	rep_len = ntohs((uint16_t)(swap >> 16));
	
        if (rep_len == len)
                return true;
        if (rep_len == len - 4)
                return true;

        return false;
}


static inline bool match_1580_ppstream(uint32_t payload, uint32_t len) {
        if (len == 24) {
                if (MATCH(payload, 0x15, 0x80, 0x51, 0x10))
                        return true;
                if (MATCH(payload, 0x15, 0x80, 0x40, 0x01))
                        return true;
        }
        return false;
}

static inline bool match_1480_ppstream(uint32_t payload, uint32_t len) {

        if (len == 24) {
                if (MATCH(payload, 0x14, 0x80, 0x50, 0x11))
                        return true;
        }
        return false;

}

static inline bool match_1b80_ppstream(uint32_t payload, uint32_t len) {
        if (len == 27) {
                if (MATCH(payload, 0x1b, 0x80, ANY, ANY))
                        return true;
        }
        return false;
}

static inline bool match_8480_ppstream(uint32_t payload, uint32_t len) {
        if (len == 132) {
                if (MATCH(payload, 0x84, 0x80, 0xc0, 0xd1))
                        return true;
                if (MATCH(payload, 0x84, 0x80, 0xd1, 0xc0))
                        return true;
        }
        return false;
}

static inline bool match_any80_ppstream(uint32_t payload) {

        if (MATCH(payload, ANY, 0x80, ANY, ANY))
                return true;
        return false;
}

static inline bool match_ppstream(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_1580_ppstream(data->payload[0], data->payload_len[0])) {
                if (match_1b80_ppstream(data->payload[1], data->payload_len[1]))
                        return true;
                if (match_1580_ppstream(data->payload[1], data->payload_len[1]))
                        return true;
                if (match_1480_ppstream(data->payload[1], data->payload_len[1]))
                        return true;
                if (match_any80_ppstream(data->payload[1]))
                        return true;
        }

        if (match_1580_ppstream(data->payload[1], data->payload_len[1])) {
                if (match_1b80_ppstream(data->payload[0], data->payload_len[0]))
                        return true;
                if (match_1580_ppstream(data->payload[0], data->payload_len[0]))
                        return true;
                if (match_1480_ppstream(data->payload[0], data->payload_len[0]))
                        return true;
                if (match_any80_ppstream(data->payload[0]))
                        return true;
        }

        if (match_8480_ppstream(data->payload[0], data->payload_len[0])) {
                if (match_any80_ppstream(data->payload[1]))
                        return true;
        }

        if (match_8480_ppstream(data->payload[1], data->payload_len[1])) {
                if (match_any80_ppstream(data->payload[0]))
                        return true;
        }

	if (!match_ppstream_payload(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_ppstream_payload(data->payload[1], data->payload_len[1]))
                return false;

        return true;


}

static lpi_module_t lpi_ppstream = {
	LPI_PROTO_UDP_PPSTREAM,
	LPI_CATEGORY_P2PTV,
	"PPStream",
	5,
	match_ppstream
};

void register_ppstream(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ppstream, mod_map);
}

