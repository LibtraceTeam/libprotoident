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

static inline bool match_vmware_banner(uint32_t payload) {
        if (MATCH(payload, '2', '2', '0', 0x20))
                return true;
        return false;
}

static inline bool match_vmware_ssl(uint32_t payload) {
        if (MATCH(payload, 0x16, 0x03, 0x01, 0x00))
                return true;
        return false;
}

static inline bool match_vmware(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Require port 902 to avoid confusion with other SSL or "220 "
         * protocols */
        if (data->server_port != 902 && data->client_port != 902)
                return false;

        if (match_vmware_banner(data->payload[0])) {
                if (match_vmware_ssl(data->payload[1]))
                        return true;
        }

        if (match_vmware_banner(data->payload[1])) {
                if (match_vmware_ssl(data->payload[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_vmware = {
	LPI_PROTO_VMWARE,
	LPI_CATEGORY_CLOUD,
	"VMWare",
	125,
	match_vmware
};

void register_vmware(LPIModuleMap *mod_map) {
	register_protocol(&lpi_vmware, mod_map);
}

