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

/* Open source encrypted skype replacement */

static inline bool match_tox_get(uint32_t payload, uint32_t len) {

        if (len == 113 && MATCH(payload, 0x02, ANY, ANY, ANY))
                return true;
        return false;

}

static inline bool match_tox_reply(uint32_t payload, uint32_t len) {
        
        /* Not sure on these length restrictions */
        if (len == 238 && MATCH(payload, 0x04, ANY, ANY, ANY))
                return true;
        if (len == 354 && MATCH(payload, 0x83, ANY, ANY, ANY))
                return true;
        if (len == 387 && MATCH(payload, 0x82, ANY, ANY, ANY))
                return true;
        return false;

}

static inline bool match_tox(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->server_port != 33445 && data->client_port != 33445) {
                return false;
        }

        if (match_tox_get(data->payload[0], data->payload_len[0])) {
                if (match_tox_reply(data->payload[1], data->payload_len[1])) {
                        return true;
                }
        }
        if (match_tox_get(data->payload[1], data->payload_len[1])) {
                if (match_tox_reply(data->payload[0], data->payload_len[0])) {
                        return true;
                }
        }

	return false;
}

static lpi_module_t lpi_tox = {
	LPI_PROTO_UDP_TOX,
	LPI_CATEGORY_CHAT,
	"ToxUDP",
	110,
	match_tox
};

void register_tox(LPIModuleMap *mod_map) {
	register_protocol(&lpi_tox, mod_map);
}

