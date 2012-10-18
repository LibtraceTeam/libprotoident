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
 * $Id: lpi_zeroaccess_udp.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* This protocol is used by the ZeroAccess Trojan for P2P communication
 * between infected hosts.
 *
 * http://www.kindsight.net/sites/default/files/Kindsight_Malware_Analysis-New_CC_protocol_ZeroAccess-final2.pdf
 */

static inline bool using_zeroaccess_port(lpi_data_t *data) {

	switch(data->server_port) {
		case 16464:
		case 16465:
		case 16470:
		case 16471:
			return true;
	}

	switch(data->client_port) {
		case 16464:
		case 16465:
		case 16470:
		case 16471:
			return true;
	}

	return false;
}

static inline bool match_zeroaccess_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* ZeroAccess uses specific ports for talking to peers */
	if (!using_zeroaccess_port(data)) {
		return false;
	}

	/* The infected host always sends a 16 byte UDP packet to the
	 * peer  - the response packet size is based solely on what we've
	 * observed in the wild.
	 *
	 * Since both payloads begin with a 32 byte checksum, we can't
	 * do much based on payload patterns */

	/* Pretty unlikely that the CRC will be exactly 0, but 0 is a
	 * common payload for other UDP protocols */
	if (data->payload[0] == 0 || data->payload[1] == 0)
		return false;

	if (data->payload_len[0] == 16) {
		if (data->payload_len[1] == 848)
			return true;
		if (data->payload_len[1] == 988)
			return true;
	}
	if (data->payload_len[1] == 16) {
		if (data->payload_len[0] == 848)
			return true;
		if (data->payload_len[0] == 988)
			return true;
	}

	return false;
}

static lpi_module_t lpi_zeroaccess_udp = {
	LPI_PROTO_UDP_ZEROACCESS,
	LPI_CATEGORY_MALWARE,
	"ZeroAccess_UDP",
	20,
	match_zeroaccess_udp
};

void register_zeroaccess_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_zeroaccess_udp, mod_map);
}

