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

static inline bool match_holla_header(uint32_t payload, uint32_t len) {

        uint32_t hdrlen;
        uint16_t swapped;

        hdrlen = ntohl(payload) >> 16;
        swapped = bswap_be_to_host16((uint16_t)hdrlen);

        if (len == swapped && MATCH(payload, ANY, ANY, 0x01, 0x00))
                return true;

        return false;

}

static inline bool restrict_port(uint16_t porta, uint16_t portb) {
        if (porta == 5888 || portb == 5888)
                return true;
        if (porta >= 4000 && porta <= 4010)
                return true;
        if (portb >= 4000 && portb <= 4010)
                return true;
        return false;
}

static inline bool match_hollachat(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Ports 5888 and 4000-4009 are common */
        if (restrict_port(data->server_port, data->client_port) == false) {
                return false;
        }

        if (match_holla_header(data->payload[0], data->payload_len[0])) {
                if (match_holla_header(data->payload[1], data->payload_len[1]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_hollachat = {
	LPI_PROTO_UDP_HOLLA,
	LPI_CATEGORY_CHAT,
	"HollaChat",
	210,
	match_hollachat
};

void register_hollachat(LPIModuleMap *mod_map) {
	register_protocol(&lpi_hollachat, mod_map);
}

