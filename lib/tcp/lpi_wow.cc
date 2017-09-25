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

static inline bool match_wow_request(uint32_t payload, uint32_t len) {

        if (!MATCH(payload, 0x00, 0x08, ANY, 0x00))
                return false;

        payload = ntohl(payload);

        /* 3rd and 4th bytes are the size of the packet, minus the four
         * byte header */
        if (htons(payload & 0xffff) == len - 4)
                return true;

        return false;
}

static inline bool match_wow_response(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;

        if (len != 119)
                return false;

        if (!MATCH(payload, 0x00, 0x00, 0x00, ANY))
                return false;

        return true;

}

static inline bool match_wow_s2c(uint32_t payload, uint32_t len) {
	/* WoW seems to have changed the server to client protocol recently,
	 * possibly with the new expansion Cataclysm */

	if (len == 0)
		return true;
	if (len != 50)
		return false;
	if (MATCH(payload, 0x30, 0x00, 0x57, 0x4f))
		return true;
	return false;
}


static inline bool match_wow_2016(uint32_t payload, uint32_t len) {
        if (len == 47 || len == 48) {
                if (MATCHSTR(payload, "WORL"))
                        return true;
        }
        return false;

}


static inline bool match_china_wow(uint32_t payload, uint32_t len) {
        if (len == 57 || len == 59) {
                if (MATCH(payload, 0x05, 0x01, 0x93, 0x01))
                        return true;
        }
        return false;

}



static inline bool match_wow(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	 if (match_wow_request(data->payload[0], data->payload_len[0])) {
                if (match_wow_response(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_wow_request(data->payload[1], data->payload_len[1])) {
                if (match_wow_response(data->payload[0], data->payload_len[0]))
                        return true;
        }

	if (match_wow_s2c(data->payload[0], data->payload_len[0])) {
		if (match_wow_s2c(data->payload[1], data->payload_len[1]))
			return true;
	}
	
        if (data->server_port == 3724 || data->client_port == 3724) {
                /* New initial exchange observed in packet traces from 2016 */
                if (match_wow_2016(data->payload[0], data->payload_len[0]) &&
                                match_wow_2016(data->payload[1],
                                                data->payload_len[1])) {
                        return true;
                }
        }

        /* Chinese WOW is a little different */
        if (data->server_port == 8001 || data->client_port == 8001) {
                if (match_wow_2016(data->payload[0], data->payload_len[0])) {
                        if (match_wow_2016(data->payload[1], data->payload_len[1]))
                                return true;

                        if (match_china_wow(data->payload[1], data->payload_len[1]))
                                return true;
                }

                if (match_wow_2016(data->payload[1], data->payload_len[1])) {
                        if (match_china_wow(data->payload[0], data->payload_len[0]))
                                return true;
                }
        }


	return false;
}

static lpi_module_t lpi_wow = {
	LPI_PROTO_WOW,
	LPI_CATEGORY_GAMING,
	"WorldOfWarcraft",
	4,	/* Not super-strong, especially for one-way */
	match_wow
};

void register_wow(LPIModuleMap *mod_map) {
	register_protocol(&lpi_wow, mod_map);
}

