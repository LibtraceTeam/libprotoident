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
#include <stdio.h>

static inline bool ppstream_pattern(uint32_t payload) {

	if (MATCH(payload, ANY, ANY, 0x43, 0x00))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x22))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x23))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x32))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x46))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x47))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x49))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x4c))
		return true;
	if (MATCH(payload, ANY, ANY, 0x43, 0x4d))
		return true;

	return false;

}

static inline bool match_ppstream_payload(uint32_t payload, uint32_t len) {
        uint16_t rep_len = 0;
	uint32_t swap = ntohl(payload);

        if (len == 0)
                return true;

	/* Seems to be used on start-up to check access to certain
	 * servers owned by PPStream */
	if (MATCH(payload, 'e', 'c', 'h', 'o') && len == 5)
		return true;

        if (!ppstream_pattern(payload)) 
                return false;

        /* First two bytes are either len or len - 4 */

	rep_len = ntohs((uint16_t)(swap >> 16));
	
        if (rep_len == len)
                return true;
        if (rep_len == len - 4)
                return true;

        return false;
}


static inline bool match_ppstream(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!match_ppstream_payload(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_ppstream_payload(data->payload[1], data->payload_len[1]))
                return false;

        return true;


}

static lpi_module_t lpi_ppstream = {
	LPI_PROTO_UDP_PPSTREAM,
	LPI_CATEGORY_P2PTV,
	"PPStream",
	5,
	match_ppstream
};

void register_ppstream(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ppstream, mod_map);
}

