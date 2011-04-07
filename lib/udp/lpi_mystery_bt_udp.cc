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
 * $Id: lpi_mystery_4102.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* This appears to be associated with BitTorrent somehow - there are occasional
 * DHT-style bencoding dictionaries in these flows, but cannot find anything
 * to confirm this :/
 */

static inline bool match_2102_response(uint32_t payload, uint32_t other,
		uint32_t len) {

	if (len == 0)
		return true;
	if (len != 30)
		return false;

	/* Check that the last two bytes match for both directions 
	 * 
	 * Remember byte-ordering! 
	 */
	if ((payload & 0xffff0000) != (other & 0xffff0000))
		return false;
	
	if (!MATCH(payload, 0x21, 0x02, ANY, ANY))
		return false;
	

	return true;


}

static inline bool match_dict(uint32_t payload, uint32_t len) {

	/* Check for bencoded dictionary */
	if (MATCH(payload, 'd', '1', ':', 'r'))
		return true;
	if (MATCH(payload, 'd', '1', ':', 'a'))
		return true;
	if (MATCH(payload, 'd', '1', ':', 'e'))
		return true;
	if (MATCH(payload, 'd', '1', ANY, ':'))
		return true;

	return false;

}

static inline bool match_4102_request(uint32_t payload, uint32_t len) {

	if (len != 30)
		return false;
	if (MATCH(payload, 0x41, 0x02, ANY, ANY))
		return true;
	return false;

}

static inline bool match_mystery_bt_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {
	
	
	if (match_4102_request(data->payload[0], data->payload_len[0])) {
		if (match_2102_response(data->payload[1], data->payload[0], 
				data->payload_len[1]))
			return true;
		if (match_dict(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_4102_request(data->payload[1], data->payload_len[1])) {
		if (match_2102_response(data->payload[0], data->payload[1], 
				data->payload_len[0]))
			return true;
		if (match_dict(data->payload[0], data->payload_len[0]))
			return true;
	}
	return false;
}

static lpi_module_t lpi_mystery_bt_udp= {
	LPI_PROTO_UDP_MYSTERY_BT,
	LPI_CATEGORY_P2P_STRUCTURE,
	"Mystery_BitTorrent_UDP",
	9,	/* Need to be higher than Skype or Gnutella */
	match_mystery_bt_udp
};

void register_mystery_bt_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_mystery_bt_udp, mod_map);
}

