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

static inline bool match_esp_encap(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* This sucks, as the four bytes are the security association ID for
         * the flow. We can only really go on port numbers, although we can
         * identify IKE packets by looking for the Non-ESP marker (which is
         * all zeroes)
         *
         * Just have to match on ports, I guess :(
         */

        if (data->server_port == 4500 && data->client_port == 4500)
                return true;

        /* If only one port is 4500, check for the Non-ESP marker */
        if (data->server_port == 4500 || data->client_port == 4500) {
                if (data->payload[0] == 0 && data->payload[1] == 0)
                        return true;
        }


	return false;
}

static lpi_module_t lpi_esp_encap = {
	LPI_PROTO_UDP_ESP,
	LPI_CATEGORY_TUNNELLING,
	"ESP_UDP",
	200,	/* This is a pretty terrible rule */
	match_esp_encap
};

void register_esp_encap(LPIModuleMap *mod_map) {
	register_protocol(&lpi_esp_encap, mod_map);
}

