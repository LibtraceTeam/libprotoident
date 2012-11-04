/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011 The University of Waikato, Hamilton, New Zealand.
 * Author: Shane Alcock
 *
 * With contributions from:
 *      Aaron Murrihy
 *      Donald Neal
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libprotoident; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: lpi_supl.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* SUPL - protocol to support location based services */

static inline bool match_supl_out(uint32_t payload, uint32_t len) {

	/* First two bytes are a length field, followed by two bytes of version */
	if (len == 32 && MATCH(payload, 0x00, 0x20, 0x02, 0x00))
		return true;
	return false;
}

static inline bool match_supl_in(uint32_t payload, uint32_t len) {

	/* First two bytes are a length field, followed by two bytes of version */
	if (len == 18 && MATCH(payload, 0x00, 0x12, 0x02, 0x00))
		return true;
	return false;

}

static inline bool match_supl(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->server_port != 7275 && data->client_port != 7275)
		return false;

	if (match_supl_out(data->payload[0], data->payload_len[0])) {
		if (match_supl_in(data->payload[1], data->payload_len[1]))
			return true;
	}
	if (match_supl_out(data->payload[1], data->payload_len[1])) {
		if (match_supl_in(data->payload[0], data->payload_len[0]))
			return true;
	}

	return false;
}

static lpi_module_t lpi_supl = {
	LPI_PROTO_SUPL,
	LPI_CATEGORY_LOCATION,
	"SUPL",
	12,
	match_supl
};

void register_supl(LPIModuleMap *mod_map) {
	register_protocol(&lpi_supl, mod_map);
}

