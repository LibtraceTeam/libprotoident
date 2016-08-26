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

static inline bool match_aachen_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Regular UDP port 80 probes from RWTH-Aachen University for
         * research purposes. See http://137.226.113.7/ for more details.
         */

        if (data->server_port == 80 || data->client_port == 80) {
                if (data->payload_len[0] == 0) {
                        if (data->payload_len[1] != 1055)
                                return false;
                        if (MATCH(data->payload[1], 0x0d, 'S', 'C', 'A'))
                                return true;
                }

                if (data->payload_len[1] == 0) {
                        if (data->payload_len[0] != 1055)
                                return false;
                        if (MATCH(data->payload[0], 0x0d, 'S', 'C', 'A'))
                                return true;
                }
        }


	return false;
}

static lpi_module_t lpi_aachen_udp = {
	LPI_PROTO_UDP_RWTH_AACHEN,
	LPI_CATEGORY_MONITORING,
	"RWTHAachenScan",
	100,
	match_aachen_udp
};

void register_aachen_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_aachen_udp, mod_map);
}

