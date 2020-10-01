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
 * 239.192.27.192 10.1.1.215 2222 2222 17 1599194119.713 1599194136.242 0 527360 00000000 .... 0 02000280 .... 80
 * 10.1.1.215 10.1.1.200 2222 2222 17 1599194119.716 1599194136.397 187488 0 02000280 .... 56 00000000 .... 0
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_cip(lpi_data_t *data) {

	if (MATCH(data->payload[0], 0x02, 0x00, 0x02, 0x80) &&
            MATCH(data->payload[1], 0x00, 0x00, 0x00, 0x00))
		return true;

	if (MATCH(data->payload[1], 0x02, 0x00, 0x02, 0x80) &&
            MATCH(data->payload[0], 0x00, 0x00, 0x00, 0x00))
		return true;

	return false;
}

static inline bool match_cip_io(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->server_port != 2222 && data->client_port != 2222)
		return false;

	if (match_cip(data))
		return true;

	return false;
}

static lpi_module_t lpi_cip_io = {
	LPI_PROTO_UDP_CIP_IO,
	LPI_CATEGORY_ICS,
	"CIP_I/O",
	100,
	match_cip_io
};

void register_cip_io(LPIModuleMap *mod_map) {
	register_protocol(&lpi_cip_io, mod_map);
}

