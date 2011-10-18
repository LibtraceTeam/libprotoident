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

static inline bool match_yahoo_error(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Yahoo seems to respond to HTTP errors in a really odd way - it
         * opens up a new connection and just sends raw HTML with the
         * error message in it. Not sure how they expect that to work, though.
         */

        if (data->payload_len[0] != 0 && data->payload_len[1] != 0)
                return false;

        /* The html isn't entirely valid either - they start with <HEAD>
         * rather than <HTML>...
         */
        if (match_str_either(data, "<HEA"))
                return true;


	return false;
}

static lpi_module_t lpi_yahoo_error = {
	LPI_PROTO_YAHOO_ERROR,
	LPI_CATEGORY_CHAT,
	"YahooError",
	10,	/* This rule is a bit odd */
	match_yahoo_error
};

void register_yahoo_error(LPIModuleMap *mod_map) {
	register_protocol(&lpi_yahoo_error, mod_map);
}

