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
 * $Id$
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_kik(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* This rule tries to match the traffic for Kik, a somewhat popular
	 * IM app for mobile devices. 
	 *
	 * The problem with Kik is that it uses port 5223 and SSL, so it is
	 * very difficult to distinguish from ApplePush
	 */ 

	if (!match_ssl(data))
		return false;
	
	/* Port 5223 is used */
	if (data->server_port != 5223 && data->client_port != 5223)
		return false;

	/* The key to matching Kik is bytes 3 and 4 of the incoming SSL
	 * handshake packet. They are slightly different to those seen
	 * for ApplePush flows.
	 */
	
	if (MATCH(data->payload[0], 0x16, 0x03, 0x01, 0x0c))
		return true;
	if (MATCH(data->payload[1], 0x16, 0x03, 0x01, 0x0c))
		return true;
	if (MATCH(data->payload[0], 0x16, 0x03, 0x03, 0x0e))
		return true;
	if (MATCH(data->payload[1], 0x16, 0x03, 0x03, 0x0e))
		return true;
	if (MATCH(data->payload[0], 0x16, 0x03, 0x01, 0x0e))
		return true;
	if (MATCH(data->payload[1], 0x16, 0x03, 0x01, 0x0e))
		return true;

	return false;
}

static lpi_module_t lpi_kik = {
	LPI_PROTO_KIK,
	LPI_CATEGORY_CHAT,
	"Kik",
	5, /* Should be a higher priority than ApplePush */
	match_kik
};

void register_kik(LPIModuleMap *mod_map) {
	register_protocol(&lpi_kik, mod_map);
}

