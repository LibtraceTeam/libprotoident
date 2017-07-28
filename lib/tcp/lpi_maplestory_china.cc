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

static inline bool match_cms_hello(uint32_t payload, uint32_t len) {

        if (len == 16 || len == 536) {
                if (MATCH(payload, 0x0e, 0x00, 0x8d, 0x00))
                        return true;
                if (MATCH(payload, 0x0e, 0x00, 0x8e, 0x00))
                        return true;
                if (MATCH(payload, 0x0e, 0x00, 0x8f, 0x00))
                        return true;
                if (MATCH(payload, 0x0e, 0x00, 0x90, 0x00))
                        return true;
        }
        return false;

}

static inline bool match_cms_alt(uint32_t payload, uint32_t len) {

        if (len == 16) {
                if (MATCH(payload, 0x0e, 0x00, 0xba, 0x00))
                        return true;
                if (MATCH(payload, 0x0e, 0x00, 0xbb, 0x00))
                        return true;
        }
        return false;
}

static inline bool match_maplestory_china(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Can also restrict to ports 8585 and 8586 if required */

        if (match_cms_hello(data->payload[0], data->payload_len[0])) {
                if (data->payload_len[1] == 42)
                        return true;
        }

        if (match_cms_hello(data->payload[1], data->payload_len[1])) {
                if (data->payload_len[0] == 42)
                        return true;
        }

        if (match_cms_alt(data->payload[0], data->payload_len[0])) {
                if (data->payload_len[1] == 40)
                        return true;
        }

        if (match_cms_alt(data->payload[1], data->payload_len[1])) {
                if (data->payload_len[0] == 40)
                        return true;
        }

	return false;
}

static lpi_module_t lpi_maplestory_china = {
	LPI_PROTO_MAPLESTORY_CHINA,
	LPI_CATEGORY_GAMING,
	"MaplestoryChina",
	12,
	match_maplestory_china
};

void register_maplestory_china(LPIModuleMap *mod_map) {
	register_protocol(&lpi_maplestory_china, mod_map);
}

