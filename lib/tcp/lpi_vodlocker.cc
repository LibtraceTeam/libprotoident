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

/* Vodlocker is basically HTTP, but it uses a non-standard port (8777) and
 * the capitalisation on the HTTP responses can be a bit inconsistent.
 * Rather than pollute HTTP with this crap, I think we can get away with
 * having a separate rule for it */

static inline bool match_vodlocker(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->server_port != 8777 && data->client_port != 8777)
                return false;

        if (MATCH(data->payload[0], 'G', 'E', 'T', 0x20)) {
                if (MATCH(data->payload[1], 'H', 't', 'T', 'P'))
                        return true;
                if (MATCH(data->payload[1], 'H', 'T', 'T', 'P'))
                        return true;
        }

        if (MATCH(data->payload[1], 'G', 'E', 'T', 0x20)) {
                if (MATCH(data->payload[0], 'H', 't', 'T', 'P'))
                        return true;
                if (MATCH(data->payload[0], 'H', 'T', 'T', 'P'))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_vodlocker = {
	LPI_PROTO_VODLOCKER,
	LPI_CATEGORY_WEB,
	"Vodlocker",
	100,
	match_vodlocker
};

void register_vodlocker(LPIModuleMap *mod_map) {
	register_protocol(&lpi_vodlocker, mod_map);
}

