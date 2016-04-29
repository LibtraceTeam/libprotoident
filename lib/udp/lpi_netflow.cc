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

static inline bool match_netflow(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* NetFlow is one-way only */
	if (data->payload_len[0] != 0 && data->payload_len[1] != 0)
		return false;
	
	/* Force port requirement for now */
	if (data->server_port != 9996 && data->client_port != 9996)
		return false;

	/* Match NetFlow version 5 */
	if (MATCH(data->payload[0], 0x00, 0x05, 0x00, ANY))
		return true;
	if (MATCH(data->payload[1], 0x00, 0x05, 0x00, ANY))
		return true;
	/* Match NetFlow version 9 */
	if (MATCH(data->payload[0], 0x00, 0x09, 0x00, ANY))
		return true;
	if (MATCH(data->payload[1], 0x00, 0x09, 0x00, ANY))
		return true;
	
	return false;
}

static lpi_module_t lpi_netflow = {
	LPI_PROTO_UDP_NETFLOW,
	LPI_CATEGORY_MONITORING,
	"NetFlow",
	14,
	match_netflow
};

void register_netflow(LPIModuleMap *mod_map) {
	register_protocol(&lpi_netflow, mod_map);
}

