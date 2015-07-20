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
 * $Id: lpi_db2.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_db2_query(uint32_t payload, uint32_t len) {

        if (len != 20)
                return false;

        if (!MATCHSTR(payload, "DB2G"))
                return false;
        return true;

}

static inline bool match_db2_response(uint32_t payload, uint32_t len) {
        if (len == 0)
                return true;

        return false;

}

static inline bool match_db2(lpi_data_t *data, lpi_module_t *mod UNUSED) {
        /* Only ever seen this as scan traffic so far, so no idea what the
         * response should look like.
         */

        /* Assume port 523 for now */
        if (data->server_port != 523 && data->client_port != 523)
                return false;

        if (match_db2_query(data->payload[0], data->payload_len[0])) {
                if (match_db2_response(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_db2_query(data->payload[1], data->payload_len[1])) {
                if (match_db2_response(data->payload[0], data->payload_len[0]))
                        return true;
        }
	return false;
}

static lpi_module_t lpi_db2 = {
	LPI_PROTO_UDP_DB2,
	LPI_CATEGORY_DATABASES,
	"IBM-DB2",
	6,
	match_db2
};

void register_db2(LPIModuleMap *mod_map) {
	register_protocol(&lpi_db2, mod_map);
}

