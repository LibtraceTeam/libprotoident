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

static inline bool match_rdp_sizes(lpi_data_t *data) {

	/* This should match the common packet sizes we see for genuine
	 * RDP traffic */

	if (data->payload_len[0] == 11 || data->payload_len[0] == 19) {
		if (data->payload_len[1] == 19)
			return true;
		if (data->payload_len[1] >= 30 && data->payload_len[1] <= 47)
			return true;
	}

	if (data->payload_len[1] == 11 || data->payload_len[1] == 19) {
		if (data->payload_len[0] == 19)
			return true;
		if (data->payload_len[0] >= 30 && data->payload_len[0] <= 47)
			return true;
	}

	return false;
}

static inline bool match_rdp_port(lpi_data_t *data) {

	/* To try and avoid confusing RDP with other protocols that rely
	 * on TPKT, most notably H.323, I've had to add a port requirement
	 * here */
	 
	if (data->server_port == 3389 || data->client_port == 3389)
		return true;
	return false;
}

	

static bool match_rdp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* RDP is transported via TPKT */
	if (!match_tpkt(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_tpkt(data->payload[1], data->payload_len[1]))
		return false;
	
	if (match_rdp_port(data))
		return true;
	if (match_rdp_sizes(data))
		return true;
	

#if 0
	if (match_tpkt(data->payload[0], data->payload_len[0])) {
		if (match_tpkt(data->payload[1], data->payload_len[1]))
			return true;
		
		/* Some RDP responses seem to be encrypted - not sure if this
		 * payload length is common to all flows */
		if (data->payload_len[1] == 309) 
			return true;
	}
	if (match_tpkt(data->payload[1], data->payload_len[1])) {
		if (data->payload_len[0] == 309) 
			return true;
	}
#endif
	return false;
}

static lpi_module_t lpi_rdp = {
	LPI_PROTO_RDP,
	LPI_CATEGORY_REMOTE,
	"RDP",
	4, /*  Moving this to 4 purely on gut feeling */
	match_rdp
};

void register_rdp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_rdp, mod_map);
}
