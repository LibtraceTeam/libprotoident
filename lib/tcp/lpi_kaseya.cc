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

static inline bool match_kaseya_req(uint32_t payload, uint32_t len) {

	/* Seen quite a few flows where only the response is present */
	if (len == 0)
		return true;

	if (!MATCH(payload, 0x4a, 0x5e, 0x7a, 0x04))
		return false;
	if (len == 48)
		return true;
	if (len == 52)
		return true;
	if (len == 25)
		return true;
	return false;		

}

static inline bool match_kaseya_resp(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;

	if (!MATCH(payload, 0x4a, 0x5e, 0x7a, 0x04))
		return false;

	/*
	if (len < 200)
		return false;
	*/
	
	return true;
}

static inline bool match_kaseya(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_kaseya_req(data->payload[0], data->payload_len[0])) {
		if (match_kaseya_resp(data->payload[1], data->payload_len[1]))
			return true;
	}
	
	if (match_kaseya_req(data->payload[1], data->payload_len[1])) {
		if (match_kaseya_resp(data->payload[0], data->payload_len[0]))
			return true;
	}

	return false;
}

static lpi_module_t lpi_kaseya = {
	LPI_PROTO_KASEYA,
	LPI_CATEGORY_REMOTE,
	"Kaseya",
	7,
	match_kaseya
};

void register_kaseya(LPIModuleMap *mod_map) {
	register_protocol(&lpi_kaseya, mod_map);
}

