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

static inline bool match_web_junk(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Connections to web servers where the client clearly is not
         * speaking HTTP.
         *
         * XXX Check flows matching this occasionally for new HTTP request
         * types that we've missed :( 
         */
        if (data->payload_len[0] == 0 || data->payload_len[1] == 0)
                return false;

        if (!match_http_request(data->payload[0], data->payload_len[0])) {
                if (MATCHSTR(data->payload[1], "HTTP"))
                        return true;
        }

        if (!match_http_request(data->payload[1], data->payload_len[1])) {
                if (MATCHSTR(data->payload[0], "HTTP"))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_web_junk = {
	LPI_PROTO_WEB_JUNK,
	LPI_CATEGORY_MIXED,
	"Web_Junk",
	200,
	match_web_junk
};

void register_web_junk(LPIModuleMap *mod_map) {
	register_protocol(&lpi_web_junk, mod_map);
}

