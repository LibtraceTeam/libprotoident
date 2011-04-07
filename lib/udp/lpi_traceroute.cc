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

static inline bool match_traceroute(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* The iVMG people put payload in their traceroute packets that
         * we can easily identify */

        if (match_str_either(data, "iVMG"))
                return true;

	/* This seems to be part of some traceroute-like behaviour - the
	 * port is never incremented and the destination address is always
	 * X.X.X.1 */
	if (data->payload_len[0] == 0) {
		if (!MATCH(data->payload[1], ANY, ANY, 0x00, 0x00))
			return false;
		if (data->payload_len[1] != 16)
			return false;
		if (data->server_port != 33435 && data->client_port != 33435)
			return false;
		return true;
	}

	if (data->payload_len[1] == 0) {
		if (!MATCH(data->payload[0], ANY, ANY, 0x00, 0x00))
			return false;
		if (data->payload_len[0] != 16)
			return false;
		if (data->server_port != 33435 && data->client_port != 33435)
			return false;
		return true;
	}
	return false;
}

static lpi_module_t lpi_traceroute = {
	LPI_PROTO_UDP_TRACEROUTE,
	LPI_CATEGORY_MONITORING,
	"Traceroute_UDP",
	2,
	match_traceroute
};

void register_traceroute(LPIModuleMap *mod_map) {
	register_protocol(&lpi_traceroute, mod_map);
}

