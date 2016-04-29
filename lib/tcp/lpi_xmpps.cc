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

static inline bool match_gtalk(lpi_data_t *data) {

	/* This rule matches the encrypted traffic sent to google talk
	 * clients */ 

	if (!match_ssl(data))
		return false;
	
	/* Port 5228 is used for this */
	if (data->server_port != 5228 && data->client_port != 5228)
		return false;

	/* Try and avoid false positives using payload size checks */

	if (data->payload_len[0] == 80 ||
			data->payload_len[0] == 120 ||
			data->payload_len[0] == 118 ||
			data->payload_len[0] == 184)
		return true;
	
	if (data->payload_len[1] == 80 ||
			data->payload_len[1] == 120 ||
			data->payload_len[1] == 118 ||
			data->payload_len[1] == 184)
		return true;

	return false;
}

static inline bool match_facebook_chat(lpi_data_t *data) {

	/* This rule matches the encrypted traffic sent to facebook chat
	 * clients */ 

	if (!match_ssl(data))
		return false;
	
	/* Port 5228 is used for this */
	if (data->server_port != 8883 && data->client_port != 8883)
		return false;

	return true;
}

static inline bool match_xmpps(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_gtalk(data))
		return true;
	if (match_facebook_chat(data))
		return true;

	return false;

}

static lpi_module_t lpi_xmpps = {
	LPI_PROTO_XMPPS,
	LPI_CATEGORY_CHAT,
	"XMPPS",
	10, 
	match_xmpps
};

void register_xmpps(LPIModuleMap *mod_map) {
	register_protocol(&lpi_xmpps, mod_map);
}

