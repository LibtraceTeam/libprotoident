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

static inline bool match_akamai_tcp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* TCP exchanges between Akamai nodes */

	/* Seems to always be over port 9050, so add a check if too many
	 * false positives */

	/* Payload is 00000000 in both directions */
	if (data->payload[0] != 0 || data->payload[0] != 0)
		return false;
	if (data->payload_len[0] == 163 && data->payload_len[1] == 149)
		return true;
	if (data->payload_len[1] == 163 && data->payload_len[0] == 149)
		return true;

	return false;
}

static lpi_module_t lpi_akamai_tcp = {
	LPI_PROTO_AKAMAI,
	LPI_CATEGORY_CDN,
	"AkamaiTCP",
	9,
	match_akamai_tcp
};

void register_akamai_tcp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_akamai_tcp, mod_map);
}

