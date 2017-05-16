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

static inline bool valid_port(uint16_t porta, uint16_t portb) {

        if (porta == 9296 || portb == 9296)
                return true;
        if (porta == 9297 || portb == 9297)
                return true;

        return false;
}

static inline bool match_ps4_remoteplay(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (!valid_port(data->server_port, data->client_port))
                return false;

        /* Examples that I have are 88 bytes, but this probably depends on
         * lengths of user and device names */
        if (data->payload_len[0] != data->payload_len[1])
                return false;

        if (MATCH(data->payload[0], 0x01, 0x00, 0x00, 0x00)) {
                if (MATCH(data->payload[1], 0x01, 0x00, 0x00, 0x00))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_ps4_remoteplay = {
	LPI_PROTO_UDP_PS4_REMOTEPLAY,
	LPI_CATEGORY_GAMING,
	"PS4_RemotePlay",
	150,
	match_ps4_remoteplay
};

void register_ps4_remoteplay(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ps4_remoteplay, mod_map);
}

