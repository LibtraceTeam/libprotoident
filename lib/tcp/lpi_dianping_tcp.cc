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


static inline bool match_dianping_query(uint32_t payload, uint32_t len) {
        if (len != 1)
                return false;
        if (MATCH(payload, 0x00, 0x00, 0x00, 0x00))
                return true;
        if (MATCH(payload, 0x01, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_dianping_resp(uint32_t payload, uint32_t len) {
        if (len != 1)
                return false;
        if (MATCH(payload, 0x00, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_dianping_tcp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->server_port != 80 && data->client_port != 80 && 
                        data->client_port != 443 && data->server_port != 443)
                return false;

        if (match_dianping_query(data->payload[0], data->payload_len[0])) {
                if (match_dianping_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_dianping_query(data->payload[1], data->payload_len[1])) {
                if (match_dianping_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_dianping_tcp = {
	LPI_PROTO_DIANPING,
	LPI_CATEGORY_MOBILE_APP,
	"DianpingTCP",
	210,
	match_dianping_tcp
};

void register_dianping_tcp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_dianping_tcp, mod_map);
}

