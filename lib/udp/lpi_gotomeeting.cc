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

static inline bool match_gtm_ping(uint32_t payload, uint32_t len) {

        if (len == 16 && MATCH(payload, 'P', 'I', 'N', 'G'))
                return true;
        return false;
}

static inline bool match_gtm_pong(uint32_t payload, uint32_t len) {

        if (len == 16 && MATCH(payload, 'P', 'O', 'N', 'G'))
                return true;
        return false;
}

static inline bool match_gtm_webcam(uint32_t ploada, uint32_t ploadb) {

        /* Bytes 2,3,4 match, but be careful not to match stuff like
         * 0x000000 */

        if (MATCH(ploada, ANY, 0x00, 0x00, 0x00))
                return false;

        if ((ploada & 0xffffff00) == (ploadb & 0xffffff00))
                return true;
        return false;

}

static inline bool match_gotomeeting(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* VOIP tends to be on port 8200 */

        if (match_gtm_ping(data->payload[0], data->payload_len[0])) {
                if (match_gtm_pong(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_gtm_ping(data->payload[1], data->payload_len[1])) {
                if (match_gtm_pong(data->payload[0], data->payload_len[0]))
                        return true;
        }

        /* Webcam goes over port 1853 */
        if (match_gtm_webcam(data->payload[0], data->payload[1])) {
                if (data->server_port == 1853 || data->client_port == 1853)
                        return true;
        }

	return false;
}

static lpi_module_t lpi_gotomeeting = {
	LPI_PROTO_UDP_GOTOMEETING,
	LPI_CATEGORY_VOIP,
	"GoToMeeting",
	149,
	match_gotomeeting
};

void register_gotomeeting(LPIModuleMap *mod_map) {
	register_protocol(&lpi_gotomeeting, mod_map);
}

