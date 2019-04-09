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

/* A Flash-based version of TankiX */

static inline bool to_port(uint16_t porta, uint16_t portb) {
        if (porta == 5190 || porta == 15050)
                return true;
        if (portb == 15050 || portb == 5190)
                return true;
        return false;
}

static inline bool match_to(uint32_t payload, uint32_t len) {

        if (len == 44 && MATCH(payload, 0x00, 0x2a, 0x00, 0x03))
                return true;
        return false;
}

static inline bool match_tankionline(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (!to_port(data->server_port, data->client_port)) {
                return false;
        }

        /* The other direction is random MTU-sized payload. Apologies to
         * people with small MTUs. */
        if (match_to(data->payload[0], data->payload_len[0])) {
                if (data->payload_len[1] >= 1300)
                        return true;
        }

        if (match_to(data->payload[1], data->payload_len[1])) {
                if (data->payload_len[0] >= 1300)
                        return true;
        }

	return false;
}

static lpi_module_t lpi_tankionline = {
	LPI_PROTO_TANKIONLINE,
	LPI_CATEGORY_GAMING,
	"TankiOnline",
	180,
	match_tankionline
};

void register_tankionline(LPIModuleMap *mod_map) {
	register_protocol(&lpi_tankionline, mod_map);
}

