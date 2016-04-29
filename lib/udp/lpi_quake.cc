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

static inline bool match_quake_ping(lpi_data_t *data) {

        /* The client appears to send a "ping" (which is not part of the
         * documented Quake engine protocol). The server responds with a
         * standard "ffffffff" packet */

        if (MATCHSTR(data->payload[0], "ping") && data->payload_len[0] == 4) {
                if (data->payload_len[1] == 0)
                        return true;
                if (data->payload_len[1] != 14)
                        return false;
                if (MATCHSTR(data->payload[1], "\xff\xff\xff\xff"))
                        return true;
                return false;
        }

        if (MATCHSTR(data->payload[1], "ping") && data->payload_len[1] == 4) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[0] != 14)
                        return false;
                if (MATCHSTR(data->payload[0], "\xff\xff\xff\xff"))
                        return true;
                return false;
        }

        return false;
}


static inline bool match_quake(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Trying to match generic Quake engine games - typically use port 
         * 27960 */

        if (match_quake_ping(data))
                return true;

        if (!match_str_both(data, "\xff\xff\xff\xff", "\xff\xff\xff\xff"))
                return false;
        if (data->payload_len[0] == 16) {
                if (data->payload_len[1] >= 51 && data->payload_len[1] <= 54)
                        return true;
		if (data->payload_len[1] == 33)
			return true;
                if (data->server_port == 27960 || data->client_port == 27960) {
                        if (data->payload_len[1] >= 800 && data->payload_len[1] <= 812)
                                return true;
                }

        }
        if (data->payload_len[1] == 16) {
                if (data->payload_len[0] >= 51 && data->payload_len[0] <= 54)
                        return true;
		if (data->payload_len[0] == 33)
			return true;
                if (data->server_port == 27960 || data->client_port == 27960) {
                        if (data->payload_len[0] >= 800 && data->payload_len[0] <= 812)
                                return true;
                }
        }
	

	return false;
}

static lpi_module_t lpi_quake = {
	LPI_PROTO_UDP_QUAKE,
	LPI_CATEGORY_GAMING,
	"Quake",
	6,
	match_quake
};

void register_quake(LPIModuleMap *mod_map) {
	register_protocol(&lpi_quake, mod_map);
}

