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


/* APK name = com.dianshijia.tvlive */
/* Published by New Zealand ibestv Trading Limited (?) */

static inline bool match_dsj_req(uint32_t payload, uint32_t len) {
        if (len == 20 && MATCHSTR(payload, "\xff\x03\x00\x00"))
                return true;

        return false;
}

static inline bool match_dsj_reply(uint32_t payload, uint32_t len) {
        if (len == 20 && MATCHSTR(payload, "\xff\x05\x00\x00"))
                return true;
        if (len == 20 && MATCHSTR(payload, "\xff\x03\x01\x00"))
                return true;

        return false;
}

static inline bool match_dianshijia(lpi_data_t *data, lpi_module_t *mod UNUSED) {


        if (match_dsj_req(data->payload[0], data->payload_len[0])) {
                if (match_dsj_reply(data->payload[1], data->payload_len[1]))
                        return true;
        }


        if (match_dsj_req(data->payload[1], data->payload_len[1])) {
                if (match_dsj_reply(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_dianshijia = {
	LPI_PROTO_UDP_DIANSHIJIA,
	LPI_CATEGORY_P2PTV,             /* I think... */
	"Dianshijia",
	100,
	match_dianshijia
};

void register_dianshijia(LPIModuleMap *mod_map) {
	register_protocol(&lpi_dianshijia, mod_map);
}

