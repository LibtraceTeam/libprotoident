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

static inline bool match_cisco_ipsec_payload(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;
        if (len == 109)
                return true;
        if (len == 93)
                return true;
        return false;

}


static inline bool match_cisco_ipsec(lpi_data_t *data, lpi_module_t *mod UNUSED) {
	/* Been seeing this on UDP port 10000, which I assume is the
         * Cisco IPSec VPN */

        if (data->server_port != 10000 && data->client_port != 10000)
                return false;

        if (!match_cisco_ipsec_payload(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_cisco_ipsec_payload(data->payload[1], data->payload_len[1]))
                return false;

        return true;


}

static lpi_module_t lpi_cisco_ipsec = {
	LPI_PROTO_UDP_CISCO_VPN,
	LPI_CATEGORY_TUNNELLING,
	"Cisco_VPN_UDP",
	8,
	match_cisco_ipsec
};

void register_cisco_ipsec(LPIModuleMap *mod_map) {
	register_protocol(&lpi_cisco_ipsec, mod_map);
}

