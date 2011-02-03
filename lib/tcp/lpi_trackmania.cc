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

static inline bool match_trackmania_3450(lpi_data_t *data) {

        /* Version of trackmania protocol usually seen on port 3450 */

        if (data->server_port != 3450 && data->client_port != 3450)
                return false;

        if (match_str_both(data, "\x23\x00\x00\x00", "\x13\x00\x00\x00")) {

                if (!match_payload_length(ntohl(data->payload[0]),
                                data->payload_len[0]))
                        return false;

                if (!match_payload_length(ntohl(data->payload[1]),
                                data->payload_len[1]))
                        return false;
                return true;
        }

        if (match_str_either(data, "\x23\x00\x00\x00")) {
                if (data->payload_len[0] == 39 && data->payload_len[1] == 0)
                        return true;
                if (data->payload_len[1] == 39 && data->payload_len[0] == 0)
                        return true;
        }

        return false;

}

static inline bool match_trackmania_2350(lpi_data_t *data) {

        /* One version of the trackmania protocol, typically seen running
         * on port 2350 */

        if (!match_payload_length(ntohl(data->payload[0]),
                        data->payload_len[0]))
                return false;

        if (!match_payload_length(ntohl(data->payload[1]),
                        data->payload_len[1]))
                return false;

        if (!match_chars_either(data, 0x1c, 0x00, 0x00, 0x00))
                return false;

        return true;

}


static inline bool match_trackmania(lpi_data_t *data, lpi_module_t *mod UNUSED) 
{
	if (match_trackmania_3450(data))
                return true;
        if (match_trackmania_2350(data))
                return true;
	

	return false;
}

static lpi_module_t lpi_trackmania = {
	LPI_PROTO_TRACKMANIA,
	LPI_CATEGORY_GAMING,
	"Trackmania",
	2,
	match_trackmania
};

void register_trackmania(LPIModuleMap *mod_map) {
	register_protocol(&lpi_trackmania, mod_map);
}

