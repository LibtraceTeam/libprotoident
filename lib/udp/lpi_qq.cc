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

static inline bool match_qq_chat(lpi_data_t *data) {

	/* QQ 2006 has a version number of 0x0f5f */
        if (match_str_both(data, "\x02\x0f\x5f\x00", "\x02\x0f\x5f\x00"))
                return true;

        if (match_str_either(data, "\x02\x0f\x5f\x00")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }

        if (match_str_both(data, "\x02\x01\x00\x00", "\x02\x01\x00\x00")) {
                if (data->payload_len[0] == 75 && data->payload_len[1] == 43)
                        return true;

                if (data->payload_len[1] == 75 && data->payload_len[0] == 43)
                        return true;
        }

        if (match_str_both(data, "\x02\x02\x00\x00", "\x02\x02\x00\x00")) {
                if (data->payload_len[0] == 83 && data->payload_len[1] == 43)
                        return true;

                if (data->payload_len[1] == 83 && data->payload_len[0] == 43)
                        return true;
        }

        if (match_str_both(data, "\x02\x03\x00\x00", "\x02\x03\x00\x00")) {
                if (data->payload_len[0] == 83 && data->payload_len[1] == 43)
                        return true;

                if (data->payload_len[1] == 83 && data->payload_len[0] == 43)
                        return true;
        }

        if (data->payload[0] == data->payload[1]) {
                if (!MATCH(data->payload[0], 0x02, ANY, ANY, ANY))
                        return false;
                if (data->server_port != 8000 && data->client_port != 8000)
                        return false;
                return true;
        }


	return false;
}

static inline bool match_qq_video(lpi_data_t *data) {

        /* Observed when using the QQ app to make video calls */

        if (match_str_both(data, "\x28\x00\x00\x00", "\x28\x00\x00\x00"))
                return true;
        return false;

}

static inline bool match_qq_length(uint32_t payload, uint32_t len) {

    uint32_t plen = (ntohl(payload) >> 8) & 0xffff;

    if (plen != len)
	return false;

    if (MATCH(payload, 0x02, ANY, ANY, ANY))
	return true;
    if (MATCH(payload, 0x3e, ANY, ANY, 0x02))
	return true;

    return false;

}

static inline bool match_qq(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_qq_chat(data))
                return true;
        if (match_qq_video(data))
                return true;

	if ((data->payload[0] & 0xff000000) == (data->payload[1] & 0xff000000)) {
	    if (!match_qq_length(data->payload[0], data->payload_len[0]))
		return false;
	    if (!match_qq_length(data->payload[1], data->payload_len[1]))
		return false;
	    return true;
	}
        return false;
}

static lpi_module_t lpi_qq = {
	LPI_PROTO_UDP_QQ,
	LPI_CATEGORY_CHAT,
	"QQ",
	23,
	match_qq
};

void register_qq(LPIModuleMap *mod_map) {
	register_protocol(&lpi_qq, mod_map);
}

