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

/* Pretty sure this is Counterstrike: Global Offensive (saw references to the
 * map 'mg_de_dust' in other flows between the same endpoints).
 */

static inline bool match_ff_csgo(lpi_data_t *data) {

        if (!match_str_both(data, "\xff\xff\xff\xff", "\xff\xff\xff\xff"))
                return false;

        if (data->payload_len[0] == 33 && data->payload_len[1] == 18)
                return true;
        if (data->payload_len[1] == 33 && data->payload_len[0] == 18)
                return true;

        if (data->payload_len[0] == 23 && data->payload_len[1] == 65)
                return true;
        if (data->payload_len[1] == 23 && data->payload_len[0] == 65)
                return true;

	return false;
}

static inline bool match_sdping(uint32_t payload) {
        if (MATCH(payload, 0x01, 0x00, 's', 'd'))
                return true;
        return false;
}

static inline bool match_sdpong(uint32_t payload) {
        if (MATCH(payload, 0x02, 0x12, 'T', 'l'))
                return true;
        return false;
}

static inline bool match_csgo(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_ff_csgo(data)) {
                return true;
        }

        if (match_sdping(data->payload[0])) {
                if (match_sdpong(data->payload[1]))
                        return true;
        }

        if (match_sdping(data->payload[1])) {
                if (match_sdpong(data->payload[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_csgo = {
	LPI_PROTO_UDP_CS_GLOBAL_OFFENSIVE,
	LPI_CATEGORY_GAMING,
	"CSGlobalOffensive",
	18,
	match_csgo
};

void register_csgo(LPIModuleMap *mod_map) {
	register_protocol(&lpi_csgo, mod_map);
}

