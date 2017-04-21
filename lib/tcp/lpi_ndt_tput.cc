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


static inline bool match_ndt_tput(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* One-way throughput test */
        if (MATCH(data->payload[0], 0x20, 0x21, 0x22, 0x23) &&
                       data->payload_len[1] == 0) {
                return true;
        }
        if (MATCH(data->payload[1], 0x20, 0x21, 0x22, 0x23) &&
                       data->payload_len[0] == 0) {
                return true;
        }

	return false;
}

static lpi_module_t lpi_ndt_tput = {
	LPI_PROTO_NDT_TPUT,
	LPI_CATEGORY_MONITORING,
	"NDTThroughput",
	100,
	match_ndt_tput
};

void register_ndt_tput(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ndt_tput, mod_map);
}

