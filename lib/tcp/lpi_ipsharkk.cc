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

/* IPSharkk P2P Proxy */

static inline bool match_ipsharkk_ssl(uint32_t payload) {

        if (MATCH(payload, 0x16, 0x03, 0x03, 0x00))
                return true;
        return false;

}

static inline bool match_ipsharkk_4f(uint32_t payload) {

        if (MATCH(payload, 0x4f, 0x1b, 0x4d, ANY))
                return true;
        return false;
}

static inline bool match_ipsharkk(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_ipsharkk_ssl(data->payload[0])) {
                if (match_ipsharkk_4f(data->payload[1]))
                        return true;
        }

        if (match_ipsharkk_ssl(data->payload[1])) {
                if (match_ipsharkk_4f(data->payload[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_ipsharkk = {
	LPI_PROTO_IPSHARKK,
	LPI_CATEGORY_TUNNELLING,
	"IPSharkk",
	15,
	match_ipsharkk
};

void register_ipsharkk(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ipsharkk, mod_map);
}

