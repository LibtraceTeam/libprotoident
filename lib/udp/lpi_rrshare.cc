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


/* RRshare aka YYets aka Zimuzu  (app.zimuzu.tv) */

static inline bool match_rr_short(uint32_t payload, uint32_t len) {
        if (len == 43 && MATCH(payload, 0x00, 0x00, 0x00, ANY))
                return true;
        if (len == 43 && MATCH(payload, 0x15, 0x00, 0x00, ANY))
                return true;
        return false;
}

static inline bool match_rr_long(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x01, 0x02, 0x00, ANY))
                return true;
        return false;
}

static inline bool match_rr_05(uint32_t payload, uint32_t len) {
        if (len == 0) {
                return true;
        }
        if (MATCH(payload, 0x05, 0x00, 0x00, ANY) && len == 1129)
                return true;
        return false;
}

static inline bool match_rrshare(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* default port 21524 */
        if (data->server_port != 21524 && data->client_port != 21524) {
                return false;
        }

        if (match_rr_short(data->payload[0], data->payload_len[0])) {
                if (match_rr_long(data->payload[1], data->payload_len[1]))
                        return true;
                if (match_rr_short(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_rr_short(data->payload[1], data->payload_len[1])) {
                if (match_rr_long(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_rr_long(data->payload[0], data->payload_len[0])) {
                if (match_rr_05(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_rr_long(data->payload[1], data->payload_len[1])) {
                if (match_rr_05(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_rrshare = {
	LPI_PROTO_UDP_RRSHARE,
	LPI_CATEGORY_P2P,
	"RRShare",
	149,
	match_rrshare
};

void register_rrshare(LPIModuleMap *mod_map) {
	register_protocol(&lpi_rrshare, mod_map);
}

