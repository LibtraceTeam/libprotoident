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
 * $Id: lpi_spotify_bcast.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* Protocol used by Spotify to find other clients on the local network */

static inline bool match_spotify_bcast(lpi_data_t *data, 
		lpi_module_t *mod UNUSED) {

	if (!match_str_either(data, "Spot"))
		return false;
	
	if (data->server_port != 57621 || data->client_port != 57621)
		return false;

	return true;
}

static lpi_module_t lpi_spotify_bcast = {
	LPI_PROTO_UDP_SPOTIFY_BROADCAST,
	LPI_CATEGORY_BROADCAST,
	"SpotifyBroadcast",
	14,
	match_spotify_bcast
};

void register_spotify_bcast(LPIModuleMap *mod_map) {
	register_protocol(&lpi_spotify_bcast, mod_map);
}

