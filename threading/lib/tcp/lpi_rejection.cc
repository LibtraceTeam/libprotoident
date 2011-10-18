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

static inline bool match_rejection(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* This is an odd one - the server allows a TCP handshake to complete,
         * but responds to any requests with a single 0x02 byte. Not sure
         * whether this is some kind of honeypot or what.
         *
         * We see this behaviour on ports 445, 1433 and 80, if we need 
         * further checking */

        if (MATCH(data->payload[0], 0x02, 0x00, 0x00, 0x00)) {
                if (data->payload_len[0] == 1)
                        return true;
        }

        if (MATCH(data->payload[1], 0x02, 0x00, 0x00, 0x00)) {
                if (data->payload_len[1] == 1)
                        return true;
        }


	return false;
}

static lpi_module_t lpi_rejection = {
	LPI_PROTO_REJECTION,
	LPI_CATEGORY_NO_CATEGORY,
	"Rejection",
	255,	/* This one must be dead last */
	match_rejection
};

void register_rejection(LPIModuleMap *mod_map) {
	register_protocol(&lpi_rejection, mod_map);
}

