/*
 *
 * Copyright (c) 2011-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libprotoident.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"
#include <stdio.h>

/* Funshion is a Chinese P2PTV application that seems to use a bunch
 * of different protocols / messages.
 */ 
static inline bool match_funshion_25(uint32_t payload, uint32_t len) {

	/* One-way flows are also common, but we'd need a stronger set
	 * of rules before I'd feel comfortable allowing this.
	 */
	
	if (len != 25)
		return false;

	
	/* The payload here is almost definitely a timestamp, but it only
	 * bears an approximate resemblance to the timestamp of the packet
	 * itself. 
	 * Sometimes it is up to a day in excess of the current timestamp,
	 * sometimes it is several hours behind.
	 *
	 * Not much chance of doing any useful matches on the payload.
	 */
	return true;
}

static inline bool match_funshion_104(uint32_t payload, uint32_t len) {

	/* The payload for these packets is all zeroes, so be careful
	 * regarding false positives, e.g. XboxLive traffic.
	 */

	if (len == 0)
		return true;
	if (len != 104)
		return false;
	if (MATCH(payload, 0x00, 0x00, 0x00, 0x00))
		return true;
	return false;

}

static inline bool match_funshion_dt(uint32_t payload, uint32_t otherlen) {

	if (otherlen != 0)
		return false;

	/* The 'command' begins with byte 4, so I'm going to try 
	 * and match all known commands rather than just allowing
	 * anything in byte 4.
	 * 
	 * We might miss a few rare commands but should get the 
	 * common ones.
	 */
	
	/* init, inline_page */
	if (MATCH(payload, 'd', 't', '=', 'i'))
		return true;

	/* dtfsp, dtjs */	
	if (MATCH(payload, 'd', 't', '=', 'd'))
		return true;

	/* play_* */	
	if (MATCH(payload, 'd', 't', '=', 'p'))
		return true;
	
	/* wt_bh */	
	if (MATCH(payload, 'd', 't', '=', 'w'))
		return true;

	/* taskflux */	
	if (MATCH(payload, 'd', 't', '=', 't'))
		return true;

	/* compress_uncompress */	
	if (MATCH(payload, 'd', 't', '=', 'c'))
		return true;

	return false;
}

static inline bool match_funshion_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_funshion_25(data->payload[0], data->payload_len[0])) {
		if (match_funshion_25(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_funshion_104(data->payload[0], data->payload_len[0])) {
		if (match_funshion_104(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_funshion_dt(data->payload[0], data->payload_len[1])) 
		return true;
	if (match_funshion_dt(data->payload[1], data->payload_len[0])) 
		return true;
	

        return false;

}

static lpi_module_t lpi_funshion_udp = {
	LPI_PROTO_UDP_FUNSHION,
	LPI_CATEGORY_P2PTV,
	"Funshion_UDP",
	50,
	match_funshion_udp
};

void register_funshion_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_funshion_udp, mod_map);
}

