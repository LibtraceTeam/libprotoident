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

static inline bool match_tftp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Read request */
        if (MATCH(data->payload[0], 0x00, 0x01, ANY, ANY)) {
                if (data->server_port != 69 && data->client_port != 69)
                        return false;
                if (data->payload_len[1] == 0)
                        return true;
                if (MATCH(data->payload[1], 0x00, 0x03, ANY, ANY))
                        return true;
                if (MATCH(data->payload[1], 0x00, 0x05, ANY, ANY))
                        return true;
        }

        if (MATCH(data->payload[1], 0x00, 0x01, ANY, ANY)) {
                if (data->server_port != 69 && data->client_port != 69)
                        return false;
                if (data->payload_len[0] == 0)
                        return true;
                if (MATCH(data->payload[0], 0x00, 0x03, ANY, ANY))
                        return true;
                if (MATCH(data->payload[0], 0x00, 0x05, ANY, ANY))
                        return true;
        }

        /* Write request */
        if (MATCH(data->payload[0], 0x00, 0x02, ANY, ANY)) {
                if (data->server_port != 69 && data->client_port != 69)
                        return false;
                if (data->payload_len[1] == 0)
                        return true;
                if (MATCH(data->payload[1], 0x00, 0x04, ANY, ANY))
                        return true;
                if (MATCH(data->payload[1], 0x00, 0x05, ANY, ANY))
                        return true;
        }

        if (MATCH(data->payload[1], 0x00, 0x02, ANY, ANY)) {
                if (data->server_port != 69 && data->client_port != 69)
                        return false;
                if (data->payload_len[0] == 0)
                        return true;
                if (MATCH(data->payload[0], 0x00, 0x04, ANY, ANY))
                        return true;
                if (MATCH(data->payload[0], 0x00, 0x05, ANY, ANY))
                        return true;
        }

	/* Some systems will switch to a different port for the file 
         * transfer itself, so the request is in a different flow */
        if (MATCH(data->payload[0], 0x00, 0x03, 0x00, 0x01)) {
                if (data->payload_len[1] == 0)
                        return true;
                if (MATCH(data->payload[1], 0x00, 0x05, ANY, ANY))
                        return true;

                /* Acks (0x04) must be 4 bytes */
                if (data->payload_len[1] != 4)
                        return false;
                if (MATCH(data->payload[1], 0x00, 0x04, 0x00, 0x01))
                        return true;
        }

        if (MATCH(data->payload[1], 0x00, 0x03, 0x00, 0x01)) {
                if (data->payload_len[0] == 0)
                        return true;
                if (MATCH(data->payload[0], 0x00, 0x05, ANY, ANY))
                        return true;

                /* Acks (0x04) must be 4 bytes */
                if (data->payload_len[0] != 4)
                        return false;
                if (MATCH(data->payload[0], 0x00, 0x04, 0x00, 0x01))
                        return true;
        }
	

	return false;
}

static lpi_module_t lpi_tftp = {
	LPI_PROTO_UDP_TFTP,
	LPI_CATEGORY_FILES,
	"TFTP",
	5,
	match_tftp
};

void register_tftp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_tftp, mod_map);
}

