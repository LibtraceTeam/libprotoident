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

static inline bool match_rtcp_payload(uint32_t payload, uint32_t len) {
        if (len == 0)
                return true;
        if (MATCH(payload, 0x81, 0xc8, 0x00, ANY))
                return true;
        if (MATCH(payload, 0x81, 0xc9, 0x00, ANY))
                return true;
        if (MATCH(payload, 0x80, 0xc9, 0x00, ANY))
                return true;
        if (MATCH(payload, 0x80, 0xc8, 0x00, ANY))
                return true;
        return false;
}


static inline bool match_rtcp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Watch out for one-way DNS... */
	if (data->payload_len[0] == 0 || data->payload_len[1] == 0) {
		if (data->server_port == 53 || data->client_port == 53)
			return false;
	}

	if (!match_rtcp_payload(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_rtcp_payload(data->payload[1], data->payload_len[1]))
                return false;
        return true;

}

static lpi_module_t lpi_rtcp = {
	LPI_PROTO_UDP_RTCP,
	LPI_CATEGORY_VOIP,
	"RTCP",
	3,
	match_rtcp
};

void register_rtcp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_rtcp, mod_map);
}

