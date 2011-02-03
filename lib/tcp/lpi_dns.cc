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

static bool match_dns_zone_transfer(lpi_data_t *data) {

        uint16_t length;
	void *ptr;

        if (data->payload_len[0] == 0 || data->payload_len[1] == 0)
                return false;

        if (data->server_port != 53 && data->client_port != 53)
                return false;

	ptr = (void *)&data->payload[0];
	length = *((uint16_t *)ptr);

        if (ntohs(length) != data->payload_len[0] - 2)
                return false;

	ptr = (void *)&data->payload[1];
	length = *((uint16_t *)ptr);

        if (ntohs(length) != data->payload_len[1] - 2)
                return false;

        return true;
}


static bool match_tcp_dns(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_dns(data))
		return true;
	if (match_dns_zone_transfer(data))
		return true;
	
	return false;

}

static lpi_module_t lpi_dns = {
	LPI_PROTO_DNS,
	LPI_CATEGORY_SERVICES,
	"DNS",
	5, 	/* Not a high certainty */
	match_tcp_dns
};

void register_dns_tcp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_dns, mod_map);
}
