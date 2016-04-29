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

static bool match_teredo_payload(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;
        if (MATCH(payload, 0x00, 0x01, 0x00, 0x00)) {
                if (len == 61 || len == 109 || len == 77)
                        return true;
        }

        /* Matching v6 traffic */
        if (MATCH(payload, 0x60, 0x00, 0x00, 0x00) && len >= 4) {
                return true;
        }

        /* We also see this in flows that have the same 5 tuple as other
         * Teredo flows */

        if (MATCH(payload, 0x00, 0x00, 0x00, 0x00))
                return false;

        if (len == 48 && MATCH(payload, 0x00, 0x00, ANY, ANY))
                return true;


        return false;

}


static inline bool match_teredo(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->server_port == 53 || data->client_port == 53) {
		if (data->payload_len[0] == 0)
	                return false;
		if (data->payload_len[1] == 0)
	                return false;
	}

        if (!match_teredo_payload(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_teredo_payload(data->payload[1], data->payload_len[1]))
                return false;

        return true;
}

static lpi_module_t lpi_teredo = {
	LPI_PROTO_UDP_TEREDO,
	LPI_CATEGORY_TUNNELLING,
	"Teredo",
	6,
	match_teredo
};

void register_teredo(LPIModuleMap *mod_map) {
	register_protocol(&lpi_teredo, mod_map);
}

