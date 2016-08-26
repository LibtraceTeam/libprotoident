/*
 *
 * Copyright (c) 2011-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libprotoident.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_isakmp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Rule out anything not on UDP port 500 */
        if (data->server_port != 500 && data->client_port != 500)
                return false;

        /* Catching one-way ISAKMP is hard, we have to rely on port numbers
         * because nothing else is consistent :( */
        if (data->payload_len[0] == 0 || data->payload_len[1] == 0) {
                if (data->server_port == 500 && data->client_port == 500)
                        return true;
                return false;
        }


        /* First four bytes are the cookie for the initiator, so should match 
         * in both directions */

        if (data->payload[0] != data->payload[1])
                return false;
        if (data->payload_len[0] < 4 && data->payload_len[1] < 4)
                return false;

        return true;

}

static lpi_module_t lpi_isakmp = {
	LPI_PROTO_UDP_ISAKMP,
	LPI_CATEGORY_KEY_EXCHANGE,
	"ISAKMP",
	6,
	match_isakmp
};

void register_isakmp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_isakmp, mod_map);
}

