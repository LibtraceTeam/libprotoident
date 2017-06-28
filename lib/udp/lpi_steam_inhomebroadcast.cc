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

static inline bool match_steam_inhomebroadcast_ports(uint16_t porta, uint16_t portb) {
	if (porta == 27036 && portb == 27036)
		return true;
	return false;
}

static inline bool match_steam_inhomebroadcast(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!match_steam_inhomebroadcast_ports(data->server_port, data->client_port))
		return false;

    if (data->payload_len[0] == 0 || data->payload_len[1] == 0) {
        if (match_str_both(data, "\xff\xff\xff\xff", "\x00\x00\x00\x00"))
            return true;    
    }

	return false;
}

static lpi_module_t lpi_steam_inhomebroadcast = {
	LPI_PROTO_UDP_STEAM_INHOMEBROADCAST,
	LPI_CATEGORY_GAMING,
	"Steam_InHome_Broadcast",
	9,
	match_steam_inhomebroadcast
};

void register_steam_inhomebroadcast(LPIModuleMap *mod_map) {
	register_protocol(&lpi_steam_inhomebroadcast, mod_map);
}

