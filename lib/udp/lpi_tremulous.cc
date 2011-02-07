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

static inline bool match_tremulous(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!MATCH(data->payload[0], 0xff, 0xff, 0xff, 0xff)) {
                if (data->payload_len[0] != 0)
                        return false;
        }
        if (!MATCH(data->payload[1], 0xff, 0xff, 0xff, 0xff)) {
                if (data->payload_len[1] != 0)
                        return false;
        }

        /* Not super confident that this won't match other traffic, so
         * added a port rule here */
        if (data->server_port != 30710 && data->client_port != 30710 &&
                        data->client_port != 30711 &&
                        data->server_port != 30711) {
                return false;
        }


        if (data->payload_len[0] >= 20 && data->payload_len[0] <= 24) {
                if (data->payload_len[1] == 0)
                        return true;
        }

        if (data->payload_len[1] >= 20 && data->payload_len[1] <= 24) {
                if (data->payload_len[0] == 0)
                        return true;
        }

        if (data->payload_len[0] >= 116 && data->payload_len[0] <= 119) {
                if (data->payload_len[1] == 0)
                        return true;
        }

        if (data->payload_len[1] >= 116 && data->payload_len[1] <= 119) {
                if (data->payload_len[0] == 0)
                        return true;
        }

        if (data->payload_len[0] == 37) {
                if (data->payload_len[1] == 98)
                        return true;
        }
        if (data->payload_len[1] == 37) {
                if (data->payload_len[0] == 98)
                        return true;
        }


	return false;
}

static lpi_module_t lpi_tremulous = {
	LPI_PROTO_UDP_TREMULOUS,
	LPI_CATEGORY_GAMING,
	"Tremulous",
	7,
	match_tremulous
};

void register_tremulous(LPIModuleMap *mod_map) {
	register_protocol(&lpi_tremulous, mod_map);
}

