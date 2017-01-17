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

static inline bool match_http_badport(lpi_data_t *data, lpi_module_t *mod) {

        /* For some reason, some clients send GET messages to servers on
         * port 443, which unsurprisingly do not respond. I'm putting this
         * in a separate category to avoid mixing it in with legitimate
         * HTTP traffic */

        if (data->payload_len[0] != 0 && data->payload_len[1] != 0)
                return false;

        if (!match_str_either(data, "GET "))
                return false;

        if (data->server_port == 443 || data->client_port == 443)
                return true;

        return false;

}

static lpi_module_t lpi_http_badport = {
	LPI_PROTO_HTTP_BADPORT,
	LPI_CATEGORY_WEB,
	"HTTP_443",
	2,
	match_http_badport
};

void register_http_badport(LPIModuleMap *mod_map) {
	register_protocol(&lpi_http_badport, mod_map);
}

