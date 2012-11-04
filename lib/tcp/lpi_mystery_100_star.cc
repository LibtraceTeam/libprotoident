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
 * $Id: lpi_mystery_100_star.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* What I do know about this protocol:
 * 	all remote hosts appear to be Korean
 * 	download volumes can be very large, so must be some form of media
 *	due to variety of remote hosts, probably P2P
 * 	does not appear to be Afreeca, Fileguri, Gorealra
 * 	no common port number
 */

static inline bool match_100(uint32_t payload, uint32_t len) {

	if (len != 15)
		return false;
	if (MATCHSTR(payload, "100 "))
		return true;
	return false;
}

static inline bool match_command(uint32_t payload, uint32_t len) {

	/* Probably short for START */
	if (len == 20 && MATCHSTR(payload, "STAR"))
		return true;

	/* DOWNLOAD ? */
	if (len == 39 && MATCHSTR(payload, "DOWN"))
		return true;

	return false;

}

static inline bool match_mystery_100_star(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_100(data->payload[0], data->payload_len[0])) {
		if (match_command(data->payload[1], data->payload_len[1]))
			return true;
	}
	if (match_100(data->payload[1], data->payload_len[1])) {
		if (match_command(data->payload[0], data->payload_len[0]))
			return true;
	}

	return false;
}

static lpi_module_t lpi_mystery_100_star = {
	LPI_PROTO_MYSTERY_100_STAR,
	LPI_CATEGORY_NO_CATEGORY,
	"Mystery_100_STAR",
	250,
	match_mystery_100_star
};

void register_mystery_100_star(LPIModuleMap *mod_map) {
	register_protocol(&lpi_mystery_100_star, mod_map);
}

