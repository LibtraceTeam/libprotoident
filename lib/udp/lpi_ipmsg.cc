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

static inline bool match_ipmsg(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	 /* IPMSG packet format:
         *
         * Version:MessageNumber:User:Host:Command:MsgContent
         *
         * Version is always 1.
         *
         * All IPMsg observed so far has a message number beginning with
         * 80...
         */

        /* Do a port check as well, just to be sure */
        if (data->server_port != 2425 && data->client_port != 2425)
                return false;

        if (match_chars_either(data, '1', ':', '8', '0'))
                return true;

        return false;
}

static lpi_module_t lpi_ipmsg = {
	LPI_PROTO_UDP_IPMSG,
	LPI_CATEGORY_CHAT,
	"IPMsg",
	5,
	match_ipmsg
};

void register_ipmsg(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ipmsg, mod_map);
}

