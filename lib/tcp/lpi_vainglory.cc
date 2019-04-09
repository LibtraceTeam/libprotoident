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

/* Vainglory -- MOBA for touch screens */

static inline bool match_vg_req(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x00, 0x86, 0x00, 0x05) && len == 136)
                return true;
        if (MATCH(payload, 0x00, 0x86, 0x00, 0x06) && len == 136)
                return true;
        return false;

}

static inline bool match_vg_resp(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x00, 0x03, 0x00, 0x07) && len == 5)
                return true;
        if (MATCH(payload, 0x00, 0x03, 0x00, 0x06) && len == 5)
                return true;
        return false;

}

static inline bool match_vainglory(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_vg_req(data->payload[0], data->payload_len[0])) {
                if (match_vg_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_vg_req(data->payload[1], data->payload_len[1])) {
                if (match_vg_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_vainglory = {
	LPI_PROTO_VAINGLORY,
	LPI_CATEGORY_GAMING,
	"Vainglory",
	5,
	match_vainglory
};

void register_vainglory(LPIModuleMap *mod_map) {
	register_protocol(&lpi_vainglory, mod_map);
}

