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

/* Ganglia -- monitoring for clusters / grid computing */

static inline bool match_gangmsg(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x00, 0x00, 0x00, 0x80)) {
                /* The payload usually contains a host name so can
                 * vary a fair bit.
                 */
                if (len >= 100 && len <= 250) {
                        return true;
                }
        }
        return false;
}

static inline bool match_ganglia(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->server_port != 8649 && data->client_port != 8649) {
                return false;
        }

        if (match_gangmsg(data->payload[0], data->payload_len[0])) {
                if (data->payload_len[1] == 0)
                        return true;
        }

        if (match_gangmsg(data->payload[1], data->payload_len[1])) {
                if (data->payload_len[0] == 0)
                        return true;
        }

	return false;
}

static lpi_module_t lpi_ganglia = {
	LPI_PROTO_UDP_GANGLIA,
	LPI_CATEGORY_MONITORING,
	"Ganglia",
	50,
	match_ganglia
};

void register_ganglia(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ganglia, mod_map);
}

