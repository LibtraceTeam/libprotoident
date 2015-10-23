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

static inline bool match_sslvpn(uint32_t payload) {

        /* Payload looks like SSL, except they've set the version field
         * to 1.0 (which would be invalid in real SSL) -- oh, Cisco!
         */
        if (MATCH(payload, 0x16, 0x01, 0x00, 0x00))
                return true;
        return false;

}

static inline bool match_cisco_sslvpn(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_sslvpn(data->payload[0]) && match_sslvpn(data->payload[1]))
                return true;

	return false;
}

static lpi_module_t lpi_cisco_sslvpn = {
	LPI_PROTO_UDP_CISCO_SSLVPN,
	LPI_CATEGORY_TUNNELLING,
	"CiscoSSLVPN",
	5,
	match_cisco_sslvpn
};

void register_cisco_sslvpn(LPIModuleMap *mod_map) {
	register_protocol(&lpi_cisco_sslvpn, mod_map);
}

