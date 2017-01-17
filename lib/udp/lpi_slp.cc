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

static inline bool match_slp_req(uint32_t payload, uint32_t len) {

        /* According to RFC 2608, the 3rd and 4th bytes should be the 
         * length (including the SLP header). This doesn't appear to be the
         * case with any of the port 427 traffic I've seen, so either I'm
         * wrong or people fail at following RFCs */

        if (MATCH(payload, 0x02, 0x01, 0x00, 0x00) && len == 49) {
                return true;
        }

        return false;

}

static inline bool match_slp_resp(uint32_t payload, uint32_t len) {

        /* I haven't actually observed any responses yet, so just going
         * on what the spec says :/ */

        if (len == 0)
                return true;

        if (MATCH(payload, 0x02, 0x02, ANY, ANY)) {
                return true;
        }

        return false;
}


static inline bool match_slp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->server_port != 427 && data->client_port != 427)
                return false;

        if (match_slp_req(data->payload[0], data->payload_len[0])) {
                if (match_slp_resp(data->payload[1], data->payload_len[1]))
                        return true;
                return false;
        }

        if (match_slp_req(data->payload[1], data->payload_len[1])) {
                if (match_slp_resp(data->payload[0], data->payload_len[0]))
                        return true;
                return false;
        }


	return false;
}

static lpi_module_t lpi_slp = {
	LPI_PROTO_UDP_SLP,
	LPI_CATEGORY_SERVICES,
	"SLP",
	5,
	match_slp
};

void register_slp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_slp, mod_map);
}

