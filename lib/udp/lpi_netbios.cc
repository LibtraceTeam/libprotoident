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

static inline bool match_netbios_req(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x80, 0xb0, 0x00, 0x00)) {
                if (len == 50)
                        return true;
                if (len == 20)
                        return true;
        }

        if (MATCH(payload, 0x80, 0x94, 0x00, 0x00)) {
                if (len == 50)
                        return true;
        }

        /* Broadcast traffic observed on our Uni network :/ */
        if (MATCH(payload, ANY, ANY, 0x01, 0x10)) {
                if (len == 50)
                        return true;

        }
        return false;

}


static inline bool match_netbios_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Haven't yet seen an actual response to Netbios lookups */

        if (match_netbios_req(data->payload[0], data->payload_len[0])) {
                if (data->payload_len[1] == 0)
                        return true;
        }

        if (match_netbios_req(data->payload[1], data->payload_len[1])) {
                if (data->payload_len[0] == 0)
                        return true;
        }

	
	return false;
}

static lpi_module_t lpi_netbios_udp = {
	LPI_PROTO_UDP_NETBIOS,
	LPI_CATEGORY_SERVICES,
	"NetBIOS_UDP",
	3,
	match_netbios_udp
};

void register_netbios_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_netbios_udp, mod_map);
}

