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

/* Custom VPN protocol used by VPN Unlimited -- OpenVPN is the default, but
 * this is also offered for "ultimate security" (at some performance cost).
 */

/* Looks like first 2 bytes are a length field */

static inline bool match_vpn_req(uint32_t payload, uint32_t len) {
        if (len == 44 && MATCH(payload, 0x00, 0x2a, 0x5e, 0x4d))
                return true;
        return false;
}

static inline bool match_vpn_resp(uint32_t payload, uint32_t len) {
        if (len == 56 && MATCH(payload, 0x00, 0x36, 0x26, 0x51))
                return true;
        return false;
}

static inline bool match_vpnunlimited_tcp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Always seen on port 443 */
        if (match_vpn_req(data->payload[0], data->payload_len[0])) {
                if (match_vpn_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_vpn_req(data->payload[1], data->payload_len[1])) {
                if (match_vpn_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_vpnunlimited_tcp = {
	LPI_PROTO_VPN_UNLIMITED,
	LPI_CATEGORY_TUNNELLING,
	"VPNUnlimitedTCP",
	10,
	match_vpnunlimited_tcp
};

void register_vpnunlimited_tcp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_vpnunlimited_tcp, mod_map);
}

