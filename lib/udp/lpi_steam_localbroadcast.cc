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
 * $Id: lpi_steam_localbroadcast.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* This protocol is something I observed on a laptop running a Steam client.
 * It just constantly spams 255.255.255.255 with these packets and I found
 * some references to Steam when trying to find out what it was, e.g.
 * http://ask.wireshark.org/questions/11566/possible-malware-on-network
 *
 */

static inline bool match_steam_ports(uint16_t port_a, uint16_t port_b) {
	
	if (port_a == 10007 || port_b == 10007)
		return true;
	if (port_a == 10019 || port_b == 10019)
		return true;
	return false;
}

static inline bool match_steam_request(uint32_t payload, uint32_t len) {

	if (len != 128)
		return false;
	if (MATCHSTR(payload, "\x00\xff\x00\x00"))
		return true;
	if (MATCHSTR(payload, "\xf0\xff\x00\x00"))
		return true;

	return false;
}
	

static inline bool match_steam_reply(uint32_t payload, uint32_t len) {

	/* Not seen a valid reply yet, so just check for no reply */
	if (len == 0)
		return true;
	return false;

}

static inline bool match_steam_localbroadcast(lpi_data_t *data, 
		lpi_module_t *mod UNUSED) {

	if (!match_steam_ports(data->server_port, data->client_port)) {
		return false;
	}

	if (match_steam_request(data->payload[0], data->payload_len[0])) {
		if (match_steam_reply(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_steam_request(data->payload[1], data->payload_len[1])) {
		if (match_steam_reply(data->payload[0], data->payload_len[0]))
			return true;
	}
	return false;
}

static lpi_module_t lpi_steam_localbroadcast = {
	LPI_PROTO_UDP_STEAM_LOCALBROADCAST,
	LPI_CATEGORY_BROADCAST,
	"SteamLocalBroadcast",
	16,
	match_steam_localbroadcast
};

void register_steam_localbroadcast(LPIModuleMap *mod_map) {
	register_protocol(&lpi_steam_localbroadcast, mod_map);
}

