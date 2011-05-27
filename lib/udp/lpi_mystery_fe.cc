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

static inline bool match_mys_fe_payload(uint32_t payload, uint32_t len) {

        uint16_t length;
        uint8_t *ptr;

        /* This appears to have a 3 byte header. First byte is always 0xfe.
         * Second and third bytes are the length (minus the 3 byte header).
         */

        if (len == 0)
                return true;

        if (!MATCH(payload, 0xfe, ANY, ANY, ANY))
                return false;

        ptr = ((uint8_t *)&payload) + 1;
        length = (*((uint16_t *)ptr));

        if (length = len - 3)
                return true;

        return false;

}


static inline bool match_mystery_fe(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Again, not entirely sure what protocol this is, but we've come up
         * with a good rule for it. 
         *
         * Every packet begins with a 3 byte header - 0xfe followed by a
         * length field
         */

	if (data->payload_len[0] == 0 || data->payload_len[1] == 0) {
		if (data->server_port == 53 || data->client_port == 53)
			return false;
	}

        if (!match_mys_fe_payload(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_mys_fe_payload(data->payload[1], data->payload_len[1]))
                return false;

        return true;
}

static lpi_module_t lpi_mystery_fe = {
	LPI_PROTO_UDP_MYSTERY_FE,
	LPI_CATEGORY_NO_CATEGORY,
	"Mystery_FE",
	250,
	match_mystery_fe
};

void register_mystery_fe(LPIModuleMap *mod_map) {
	register_protocol(&lpi_mystery_fe, mod_map);
}

