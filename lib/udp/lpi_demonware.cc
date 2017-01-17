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

static inline bool match_demonware(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* This is some sort of control channel for demonware? */
        if (data->payload_len[0] == 15 && data->payload_len[1] == 0) {
                if (MATCH(data->payload[0], 0x15, 0x02, 0x00, ANY))
                        return true;
        }

        if (data->payload_len[1] == 15 && data->payload_len[0] == 0) {
                if (MATCH(data->payload[1], 0x15, 0x02, 0x00, ANY))
                        return true;
        }


        /* Demonware bandwidth testing involves sending a series of 1024
         * byte packets to a known server - each packet has an incrementing
         * seqno, starting from zero */

        if (!match_str_both(data, "\x00\x00\x00\x00", "\x00\x00\x00\x00"))
                return false;

        if (data->payload_len[0] == 1024) {
                if (data->payload_len[1] == 0)
                        return true;
                if (data->payload_len[1] == 1024)
                        return true;
        }

        if (data->payload_len[1] == 1024) {
                if (data->payload_len[0] == 0)
                        return true;
        }

        /* Sometimes 512 bytes are used as well, but only ever one-way */
        if (data->payload_len[0] == 512) {
                if (data->payload_len[1] == 0)
                        return true;
        }
        if (data->payload_len[1] == 512) {
                if (data->payload_len[0] == 0)
                        return true;
        }

        /* Could also check for ports 3074 and 3075 if needed */


	return false;
}

static lpi_module_t lpi_demonware = {
	LPI_PROTO_UDP_DEMONWARE,
	LPI_CATEGORY_GAMING,
	"Demonware",
	4,
	match_demonware
};

void register_demonware(LPIModuleMap *mod_map) {
	register_protocol(&lpi_demonware, mod_map);
}

