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

static inline bool match_l2tp_payload(uint32_t payload, uint32_t len) {

	uint32_t hdrlen = ntohl(payload) & 0xffff;

        if (len == 0)
		return true;

        if (len != hdrlen)
                return false;

	if (!MATCH(payload, 0xc8, 0x02, ANY, ANY))
		return false;

	return true;

}

static inline bool match_l2tp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!match_l2tp_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_l2tp_payload(data->payload[1], data->payload_len[1]))
		return false;


	return true;
}

static lpi_module_t lpi_l2tp = {
	LPI_PROTO_UDP_L2TP,
	LPI_CATEGORY_TUNNELLING,
	"L2TP",
	6,
	match_l2tp
};

void register_l2tp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_l2tp, mod_map);
}

