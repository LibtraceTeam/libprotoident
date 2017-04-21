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

static inline bool match_zoom_01(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x01, 0x00, 0x02, ANY)) {
                if (len == 107 || len == 109 || len == 169)
                        return true;
        }
        if (MATCH(payload, 0x01, 0x00, 0x6c, 0x00) && len == 111)
                return true;
        return false;

}

static inline bool match_zoom_02(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x02, 0x00, 0x01, ANY) && len == 35)
                return true;
        if (MATCH(payload, 0x02, 0x00, 0x22, 0x00) && len == 37)
                return true;
        if (MATCH(payload, 0x02, 0x00, 0x24, 0x00) && len == 39)
                return true;
        return false;

}

static inline bool match_zoom_05(uint32_t payload) {
        if (MATCH(payload, 0x05, 0x10, 0x01, 0x00))
                return true;
        return false;

}

static inline bool match_zoom_stream_hello(uint32_t payload, uint32_t len) {

        /* Seen 85 and 86 so far */
        if (len >= 80 && len <= 90) {
                if (MATCH(payload, 0x1f, 0x01, 0x01, 0x00))
                        return true;
        }
        return false;

}

static inline bool match_zoom_manager(lpi_data_t *data) {

        if (data->server_port != 8801 && data->client_port != 8801) {
                return false;
        }

        /* Byte 4 must match in both directions */
        if ((data->payload[0] & 0xff000000) != (data->payload[1] & 0xff000000))
                return false;

        if (match_zoom_01(data->payload[0], data->payload_len[0])) {
                if (match_zoom_02(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_zoom_01(data->payload[1], data->payload_len[1])) {
                if (match_zoom_02(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_zoom_05(data->payload[0]) && match_zoom_05(data->payload[1]))
                return true;

	return false;
}

static inline bool match_zoom_stream(lpi_data_t *data) {

        if (match_zoom_stream_hello(data->payload[0], data->payload_len[0])) {
                if (match_zoom_stream_hello(data->payload[1], data->payload_len[1]))
                        return true;
        }

        return false;

}

static inline bool match_zoom(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_zoom_manager(data))
                return true;

        if (match_zoom_stream(data))
                return true;

        return false;
}

static lpi_module_t lpi_zoom = {
	LPI_PROTO_UDP_ZOOM,
	LPI_CATEGORY_VOIP,
	"Zoom",
	5,
	match_zoom
};

void register_zoom(LPIModuleMap *mod_map) {
	register_protocol(&lpi_zoom, mod_map);
}

