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

static inline bool match_mystery_0d(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* This protocol has driven me nuts for weeks. It's pretty easy to
         * match - one direction sends a single byte datagram containing 0x0d,
         * the other responds with a 25 byte packet beginning with 0x0a. The
         * next three bytes of the response appear to be some sort of flow id
         * that is repeated in all subsequent packets > 1 byte.
         *
         * Other codes used during the exchange are 0x0b, 0x15 and 0x1e.
         *
         * However, there appears to be no info on the Internet about what this
         * protocol is. Random ports are always used for both ends, so no help
         * there.
         *
         * TODO Figure out what the hell this is and give it a better name
         * than "mystery_0d" !
         */

        if (data->payload_len[0]==1 && MATCH(data->payload[0], 0x0d, 0, 0, 0)) {
                if (data->payload_len[1] == 25 &&
                                MATCH(data->payload[1], 0x0a, ANY, ANY, ANY))
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }

        if (data->payload_len[1]==1 && MATCH(data->payload[1], 0x0d, 0, 0, 0)) {
                if (data->payload_len[0] == 25 &&
                                MATCH(data->payload[0], 0x0a, ANY, ANY, ANY))
                        return true;
                if (data->payload_len[0] == 0)
                        return true;
        }

        /* We also see the 25 byte 0x0a packet without a matching 0x0d packet
         */

        if (data->payload_len[0] == 0) {
                if (data->payload_len[1] == 25 &&
                                MATCH(data->payload[1], 0x0a, ANY, ANY, ANY))
                        return true;
        }
        if (data->payload_len[1] == 0) {
                if (data->payload_len[0] == 25 &&
                                MATCH(data->payload[0], 0x0a, ANY, ANY, ANY))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_mystery_0d = {
	LPI_PROTO_UDP_MYSTERY_0D,
	LPI_CATEGORY_NO_CATEGORY,
	"Mystery_0D",
	250,
	match_mystery_0d
};

void register_mystery_0d(LPIModuleMap *mod_map) {
	register_protocol(&lpi_mystery_0d, mod_map);
}

