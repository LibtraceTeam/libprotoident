/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011-2015 The University of Waikato, Hamilton, New Zealand.
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

static inline bool match_icp_query(uint32_t payload, uint32_t len) {

        uint32_t stated_len = 0;

        stated_len = ntohl(payload) & 0xffff;
        if (stated_len != len)
                return false;
	
	/* Just going to match v2 for now */
	if (MATCH(payload, 0x01, 0x02, ANY, ANY))
		return true;
	return false;	


}

static inline bool match_icp_response(uint32_t payload, uint32_t len) {

        uint32_t stated_len = 0;

        stated_len = ntohl(payload) & 0xffff;
        if (stated_len != len)
                return false;
	
	/* Just going to match v2 for now */

	/* HIT */
	if (MATCH(payload, 0x02, 0x02, ANY, ANY))
		return true;
	/* MISS */
	if (MATCH(payload, 0x03, 0x02, ANY, ANY))
		return true;
	
	/* XXX we possibly could match invalid and error codes as well,
	 * but let's wait until we actually see these things */
	return false;	


}

static inline bool match_icp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_icp_query(data->payload[0], data->payload_len[0])) {
		if (match_icp_response(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_icp_query(data->payload[1], data->payload_len[1])) {
		if (match_icp_response(data->payload[0], data->payload_len[0]))
			return true;
	}

	return false;
}

static lpi_module_t lpi_icp = {
	LPI_PROTO_UDP_ICP,
	LPI_CATEGORY_CACHING,
	"ICP",
	8,	/* Must be run before RADIUS */
	match_icp
};

void register_icp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_icp, mod_map);
}

