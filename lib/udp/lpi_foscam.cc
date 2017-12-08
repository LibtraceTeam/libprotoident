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

/* All Foscam traffic begins with 0xf1. Bytes 3 and 4 are a length field */

static inline bool match_fcam_probe(uint32_t payload, uint32_t len) {

        if (len == 4 && MATCH(payload, 0xf1, 0x00, 0x00, 0x00))
                return true;
        return false;

}

static inline bool match_fcam_probereply(uint32_t payload, uint32_t len) {

        if (len == 20 && MATCH(payload, 0xf1, 0x01, 0x00, 0x10))
                return true;
        return false;

}

static inline bool match_fcam_4(uint32_t payload, uint32_t len) {

        if (len == 4 && MATCH(payload, 0xf1, 0x03, 0x00, 0x00))
                return true;
        return false;

}

static inline bool match_fcam_70(uint32_t payload, uint32_t len) {
        if (len == 4 && MATCH(payload, 0xf1, 0x70, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_fcam_32(uint32_t payload, uint32_t len) {

        if (len == 32 && MATCH(payload, 0xf1, 0x83, 0x00, 0x1c))
                return true;
        return false;
}

static inline bool match_foscam(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_fcam_4(data->payload[0], data->payload_len[0])) {
                if (match_fcam_32(data->payload[1], data->payload_len[1]))
                        return true;
                if (match_fcam_70(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_fcam_4(data->payload[1], data->payload_len[1])) {
                if (match_fcam_32(data->payload[0], data->payload_len[0]))
                        return true;
                if (match_fcam_70(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_fcam_probe(data->payload[0], data->payload_len[0])) {
                if (match_fcam_probereply(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_fcam_probe(data->payload[1], data->payload_len[1])) {
                if (match_fcam_probereply(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_foscam = {
	LPI_PROTO_UDP_FOSCAM,
	LPI_CATEGORY_IPCAMERAS,
	"Foscam",
	100,
	match_foscam
};

void register_foscam(LPIModuleMap *mod_map) {
	register_protocol(&lpi_foscam, mod_map);
}

