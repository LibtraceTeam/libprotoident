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
 * $Id: lpi_lansync_udp.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* LANSync is the protocol used by DropBox to sync data changes within the
 * local network.
 *
 * Ref: http://geeklogs.posterous.com/dropbox-lan-sync-protocol
 */

static inline bool match_lansync_disc(uint32_t payload, uint32_t len) {

	if (len == 0)
		return false;
	if (MATCH(payload, '{', '"', 'h', 'o'))
		return true;
	return false;
}

static inline bool match_lansync_udp(lpi_data_t *data, 
		lpi_module_t *mod UNUSED) {

	if (data->server_port != 17500 && data->client_port != 17500)
		return false;

	if (match_lansync_disc(data->payload[0], data->payload_len[0])) {
		if (data->payload_len[1] == 0)
			return true;
	}

	if (match_lansync_disc(data->payload[1], data->payload_len[1])) {
		if (data->payload_len[0] == 0)
			return true;
	}
	return false;
}

static lpi_module_t lpi_lansync_udp = {
	LPI_PROTO_UDP_LANSYNC,
	LPI_CATEGORY_BROADCAST,
	"LanSync_UDP",
	6,
	match_lansync_udp
};

void register_lansync_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_lansync_udp, mod_map);
}

