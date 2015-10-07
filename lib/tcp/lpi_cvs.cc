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

static inline bool match_cvs_request(uint32_t data, uint32_t len) {

	if (MATCHSTR(data, "BEGI"))
		return true;
	return false;

}

static inline bool match_cvs_response(uint32_t data, uint32_t len) {

	if (len == 0)
		return true;
	
	/* "I LOVE YOU" = auth succeeded */
	if (MATCHSTR(data, "I LO"))
		return true;
	
	/* "I HATE YOU" = auth failed */
	if (MATCHSTR(data, "I HA"))
		return true;

	/* "E <msg>" = a message */
	if (MATCH(data, 'E', ' ', ANY, ANY))
		return true;

	/* error = an error */
	if (MATCHSTR(data, "erro"))
		return true;
	
	return false;

}

static inline bool match_cvs(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_cvs_request(data->payload[0], data->payload_len[0]) &&
			match_cvs_response(data->payload[1], data->payload_len[1]))
		return true;
	
	if (match_cvs_request(data->payload[1], data->payload_len[1]) &&
			match_cvs_response(data->payload[0], data->payload_len[0]))
		return true;

	return false;
}

static lpi_module_t lpi_cvs = {
	LPI_PROTO_CVS,
	LPI_CATEGORY_RCS,
	"CVS",
	3,
	match_cvs
};

void register_cvs(LPIModuleMap *mod_map) {
	register_protocol(&lpi_cvs, mod_map);
}

