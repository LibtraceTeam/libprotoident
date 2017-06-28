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

/* .NET Message Framing Protocol */

static inline bool match_version_record(uint32_t payload, uint32_t len) {

        /* Length will probably vary */
        /* Version, mode and via records are often included in the same
         * packet */

        if (MATCH(payload, 0x00, 0x01, 0x00, 0x01))
                return true;
        return false;

}

static inline bool match_upgrade_resp(uint32_t payload, uint32_t len) {

        if (len == 1 && MATCH(payload, 0x0a, 0x00, 0x00, 0x00))
                return true;
        return false;

}

static inline bool match_netmfp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Limit to port 7150 for now -- this probably only corresponds to
         * one MS service that uses this protocol, but I'm going to play
         * it conservative.
         */

        if (data->server_port != 7150 && data->client_port != 7150)
                return false;

        if (match_version_record(data->payload[0], data->payload_len[0])) {
                if (match_upgrade_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_netmfp = {
	LPI_PROTO_NET_MFP,
	LPI_CATEGORY_WEB,
	"NET-MFP",
	199,
	match_netmfp
};

void register_netmfp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_netmfp, mod_map);
}

