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

/* Separate modules for dictionary-style DHT (which has a much stronger rule)
 * and Vuze DHTs (which are not so strong) */

static inline bool match_number_query(uint32_t payload, uint32_t len) {

	if (MATCH(payload, 0x01, 0x00, ANY, ANY))
                return true;
        if (MATCH(payload, 0x11, 0x00, ANY, ANY) && len == 20)
                return true;
	if (MATCH(payload, 0x21, 0x02, ANY, ANY) && len == 30)
                return true;
        if (MATCH(payload, 0x21, 0x00, ANY, ANY) && len == 20)
                return true;
	if (MATCH(payload, 0x31, 0x02, ANY, ANY) && len == 30)
                return true;
        if (MATCH(payload, 0x31, 0x00, ANY, ANY) && len == 20)
                return true;
	if (MATCH(payload, 0x41, 0x02, ANY, ANY) && len == 30)
                return true;
        if (MATCH(payload, 0x41, 0x00, ANY, ANY) && len == 20)
                return true;
        return false;	

}

static inline bool match_number_reply(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
        if (MATCH(payload, 0x11, 0x00, ANY, ANY) && len == 20)
                return true;
	if (MATCH(payload, 0x21, 0x02, ANY, ANY) && (len == 30 || len == 33))
                return true;
        if (MATCH(payload, 0x21, 0x00, ANY, ANY) && len == 20)
                return true;
	if (MATCH(payload, 0x31, 0x02, ANY, ANY) && len == 30)
                return true;
        if (MATCH(payload, 0x31, 0x00, ANY, ANY) && len == 20)
                return true;
	if (MATCH(payload, 0x41, 0x02, ANY, ANY) && (len == 33 || len == 30))
                return true;

	return false;
}

static inline bool match_dict_query(uint32_t payload, uint32_t len) {

	if (MATCH(payload, 'd', '1', ':', 'a'))
		return true;
	if (MATCH(payload, 'd', '1', ':', 'r'))
		return true;
	if (MATCH(payload, 'd', '1', ':', 'e'))
		return true;
	if (MATCH(payload, 'd', '1', ':', 't'))
		return true;
	if (MATCH(payload, 'd', '1', ANY, ':'))
		return true;
	
	return false;

}

static inline bool match_dict_reply(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;

	if (MATCH(payload, 'd', '1', ':', 'a'))
		return true;
	if (MATCH(payload, 'd', '1', ':', 'r'))
		return true;
	if (MATCH(payload, 'd', '1', ':', 'e'))
		return true;
	if (MATCH(payload, 'd', '1', ANY, ':'))
		return true;
	
	/* These are a bit iffy, but this seems to be what happens in
	 * response to a lot of dict queries :/ */
	if (len == 23)
		return true;
	if (len == 33)
		return true;


	return false;

}

static inline bool match_dht_dict(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_dict_query(data->payload[0], data->payload_len[0])) {
		if (match_dict_reply(data->payload[1], data->payload_len[1]))
			return true;
		if (match_number_reply(data->payload[1], data->payload_len[1]))
			return true;
	}
	
	if (match_dict_query(data->payload[1], data->payload_len[1])) {
		if (match_dict_reply(data->payload[0], data->payload_len[0]))
			return true;
		if (match_number_reply(data->payload[0], data->payload_len[0]))
			return true;
	}

	if (match_number_query(data->payload[0], data->payload_len[0])) {
		
		if (MATCH(data->payload[0], 0x01, 0x00, ANY, ANY)) {
		
			if ((data->payload[0] & 0xffff0000) != 
					(data->payload[1] & 0xffff0000))
				return false;
		}

		if (match_number_reply(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_number_query(data->payload[1], data->payload_len[1])) {
		if (MATCH(data->payload[1], 0x01, 0x00, ANY, ANY)) {
		
			if ((data->payload[0] & 0xffff0000) != 
					(data->payload[1] & 0xffff0000))
				return false;
		}
		if (match_number_reply(data->payload[0], data->payload_len[0]))
			return true;
	}

	return false;
}

static lpi_module_t lpi_dht_dict = {
	LPI_PROTO_UDP_BTDHT,
	LPI_CATEGORY_P2P_STRUCTURE,
	"BitTorrent_UDP",
	6,
	match_dht_dict
};

void register_dht_dict(LPIModuleMap *mod_map) {
	register_protocol(&lpi_dht_dict, mod_map);
}

