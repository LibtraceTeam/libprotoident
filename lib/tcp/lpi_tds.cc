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

static inline bool match_tds_response(uint32_t payload, uint32_t len) {

        uint32_t stated_len = 0;

        if (len == 0)
                return true;

        if (!MATCH(payload, 0x04, 0x01, ANY, ANY))
                return false;
        stated_len = (ntohl(payload) & 0xffff);
        if (stated_len != len)
                return false;

        return true;


}


static inline bool match_tds(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_tds_request(data->payload[0], data->payload_len[0])) {
                if (match_tds_response(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_tds_request(data->payload[1], data->payload_len[1])) {
                if (match_tds_response(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_tds = {
	LPI_PROTO_TDS,
	LPI_CATEGORY_DATABASES,
	"TDS",
	3,
	match_tds
};

void register_tds(LPIModuleMap *mod_map) {
	register_protocol(&lpi_tds, mod_map);
}

