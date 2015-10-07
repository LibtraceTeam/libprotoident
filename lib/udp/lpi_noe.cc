/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011-2015 The University of Waikato, Hamilton, New Zealand.
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
 * $Id$
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* Alcatel's New Office Environment proprietary VOIP protocol
 * Thanks to Remy Mudingay for providing traces to identify this protocol
 */

static inline bool match_noe_5byte(uint32_t payload, uint32_t plen) {

	if (plen != 5)
		return false;
	if (MATCH(payload, 0x07, ANY, ANY, ANY))
		return true;
	return false;

}

static inline bool match_noe_20byte(uint32_t payload, uint32_t plen) {

	if (plen != 20)
		return false;
	if (MATCH(payload, 0x07, ANY, ANY, ANY))
		return true;
	return false;

}

static inline bool match_noe(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->payload_len[0] == 1 && data->payload_len[1] == 1) {
		if (match_str_both(data, "\x05\x00\x00\x00", 
				"\x04\x00\x00\x00")) {
			return true;
		}
	}

	if (match_noe_5byte(data->payload[0], data->payload_len[0])) {
		if (match_noe_20byte(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_noe_5byte(data->payload[1], data->payload_len[1])) {
		if (match_noe_20byte(data->payload[0], data->payload_len[0]))
			return true;
	}
	return false;
}

static lpi_module_t lpi_noe = {
	LPI_PROTO_UDP_NOE,
	LPI_CATEGORY_VOIP,
	"NOE",
	12,
	match_noe
};

void register_noe(LPIModuleMap *mod_map) {
	register_protocol(&lpi_noe, mod_map);
}

