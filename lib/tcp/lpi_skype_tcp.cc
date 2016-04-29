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

static inline bool match_skype_tcp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* This rule matches SSL traffic sent by Skype clients
	 *
	 * It isn't clear what the TCP session is used for, though... */ 

	if (!match_ssl(data))
		return false;
	
	/* Ports 12350 and 13392 are used for these sessions */
	if (data->server_port != 12350 && data->client_port != 12350 && 
			data->server_port != 13392 &&
			data->client_port != 13392)
		return false;

	/* Other payload sizes are possible unfortunately, but rare */

	if (data->payload_len[0] == 5 ||
			data->payload_len[0] == 92 ||
			data->payload_len[0] == 89 ||
			data->payload_len[0] == 90 ||
			data->payload_len[0] == 33)
		return true;
	if (data->payload_len[1] == 5 ||
			data->payload_len[1] == 92 ||
			data->payload_len[1] == 89 ||
			data->payload_len[1] == 90 ||
			data->payload_len[1] == 33)
		return true;


	return false;
}

static lpi_module_t lpi_skype_tcp = {
	LPI_PROTO_SKYPE_TCP,
	LPI_CATEGORY_VOIP,
	"SkypeTCP",
	20, /* Should be a higher priority than regular SSL */
	match_skype_tcp
};

void register_skype_tcp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_skype_tcp, mod_map);
}

