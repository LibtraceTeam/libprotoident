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

static bool dns_req(uint32_t payload) {

        /* The flags / rcode on requests are usually all zero.
         *
         * Exceptions: CB and RD may be set 
         *
         * Remember BYTE ORDER!
         */

        if ((payload & 0xffff0000) == 0x00000000)
                return true;
        if ((payload & 0xffff0000) == 0x10000000)
                return true;
        if ((payload & 0xffff0000) == 0x00010000)
                return true;

        return false;

}

static bool match_dns(lpi_data_t *data, lpi_module_t *mod) {

	if (data->payload_len[0] == 0 || data->payload_len[1] == 0) {

                /* No response, so we have a bit of a hard time - however,
                 * most requests have a pretty standard set of flags.
                 *
                 * We'll also use the port here to help out */
                if (data->server_port != 53 && data->client_port != 53)
                        return false;
                if (data->payload_len[0] > 12 && dns_req(data->payload[0]))
                        return true;
                if (data->payload_len[1] > 12 && dns_req(data->payload[1]))
                        return true;

                return false;
        }

        if ((data->payload[0] & 0x0078ffff) != (data->payload[1] & 0x0078ffff))
                return false;

        if ((data->payload[0] & 0x00800000) == (data->payload[1] & 0x00800000))
                return false;

        return true;	

}

extern "C"
lpi_module_t * lpi_register() {
	
	lpi_module_t *mod = new lpi_module_t;

	mod->protocol = LPI_PROTO_DNS;
	strncpy(mod->name, "DNS", 255);
	mod->category = LPI_CATEGORY_SERVICES;
	mod->priority = 5; 	/* Not a high certainty */
	mod->dlhandle = NULL;
	mod->lpi_callback = match_dns;

	return mod;

}
