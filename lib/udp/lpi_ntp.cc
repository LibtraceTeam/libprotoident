/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011 The University of Waikato, Hamilton, New Zealand.
 * Author: Shane Alcock
 *
 * With contributions from:
 *      Aaron Murrihy
 *      Donald Neal
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libprotoident; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_ntp_request(uint32_t payload, uint32_t len) {

        uint8_t first;
	uint8_t *ptr;
        uint8_t version;

        if (len != 48 && len != 68)
                return false;

	ptr = (uint8_t *)&payload;
	first = *ptr;

        //first = (uint8_t) (payload);

        version = (first & 0x38) >> 3;

        if (version > 4 || version == 0)
                return false;

        return true;

}

static inline bool match_ntp_response(uint32_t payload, uint32_t len) {

        uint8_t first;
        uint8_t version;
        uint8_t mode;

        /* Server may not have replied */
        if (len == 0)
                return true;

        first = (uint8_t) (payload);

        version = (first & 0x38) >> 3;
        mode = (first & 0x07);

        if (version > 4 || version == 0)
                return false;
        if (mode == 3)
                return false;

        return true;
}


static inline bool match_ntp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Force NTP to be on port 123 */

        if (data->server_port != 123 && data->client_port != 123)
                return false;

        if (match_ntp_request(data->payload[0], data->payload_len[0])) {
                if (match_ntp_response(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_ntp_request(data->payload[1], data->payload_len[1])) {
                if (match_ntp_response(data->payload[0], data->payload_len[0]))
                        return true;
        }

	/* OK, turns out we can have NTP servers that keep sending responses
	 * without a specific request from the client */
	if (match_ntp_response(data->payload[0], data->payload_len[0]) &&
			data->payload_len[0] == 48 &&
			data->payload_len[1] == 0) {
		return true;
	}
	if (match_ntp_response(data->payload[1], data->payload_len[1]) &&
			data->payload_len[1] == 48 &&
			data->payload_len[0] == 0) {
		return true;
	}

	return false;
}

static lpi_module_t lpi_ntp = {
	LPI_PROTO_UDP_NTP,
	LPI_CATEGORY_SERVICES,
	"NTP",
	2,
	match_ntp
};

void register_ntp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ntp, mod_map);
}

