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


static inline bool match_kankan_44(uint32_t payload, uint32_t len) {
        if (len != 44)
                return false;
        if (MATCH(payload, 0x01, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_kankan_28(uint32_t payload, uint32_t len) {
        if (len != 28)
                return false;
        if (MATCH(payload, 0x01, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_kankan_140(uint32_t payload, uint32_t len) {
        if (len != 140)
                return false;
        if (MATCH(payload, 0x01, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_kankan_any(uint32_t payload, uint32_t len) {
        if (MATCH(payload, 0x01, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_xmp_04_req(uint32_t payload, uint32_t len) {
        if (len < 92)
                return false;
        if (MATCH(payload, 0x04, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_xmp_04_resp(uint32_t payload, uint32_t len) {
        if (len != 4)
                return false;
        if (MATCH(payload, 0x04, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_kankan(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->client_port != 80 && data->server_port != 80)
                return false;

        if (match_kankan_44(data->payload[0], data->payload_len[0])) {
                if (match_kankan_28(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_kankan_44(data->payload[1], data->payload_len[1])) {
                if (match_kankan_28(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_kankan_140(data->payload[0], data->payload_len[0])) {
                if (match_kankan_any(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_kankan_140(data->payload[1], data->payload_len[1])) {
                if (match_kankan_any(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_xmp_04_req(data->payload[0], data->payload_len[0])) {
                if (match_xmp_04_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_xmp_04_req(data->payload[1], data->payload_len[1])) {
                if (match_xmp_04_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_kankan = {
	LPI_PROTO_KANKAN,
	LPI_CATEGORY_STREAMING,
	"KankanTCP",
	70,
	match_kankan
};

void register_kankan_tcp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_kankan, mod_map);
}

