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

/* Zero: a modified version of QUIC crypto used by Facebook until TLS 1.3 is
 * available.
 * 
 * See http://cryptologie.net/article/321/real-world-crypto-day-2/ for a bit
 * more detail.
 */

static inline bool match_zero_fb_chlo(uint32_t payload, uint32_t len) {

        if (MATCH(payload, '1', 'Q', 'T', 'V'))
                return true;
        return false;
}


static inline bool match_zero_fb_shlo(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;
        if (MATCH(payload, '1', 'Q', 'T', 'V'))
                return true;
        if (MATCH(payload, 0x30, 0x98, 0x0c, 0x00))
                return true;
        if (MATCH(payload, 0x30, 0x9d, 0x0c, 0x00))
                return true;
        if (MATCH(payload, 0x30, 0x9c, 0x0c, 0x00))
                return true;
        return false;
}


static inline bool match_zero_facebook(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->server_port != 443 && data->client_port != 443)
                return false;

        if (match_zero_fb_chlo(data->payload[0], data->payload_len[0])) {
                if (match_zero_fb_shlo(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_zero_fb_chlo(data->payload[1], data->payload_len[1])) {
                if (match_zero_fb_shlo(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_zero_facebook = {
	LPI_PROTO_ZERO_FACEBOOK,
	LPI_CATEGORY_WEB,
	"Zero_Facebook",
	5,
	match_zero_facebook
};

void register_zero_facebook(LPIModuleMap *mod_map) {
	register_protocol(&lpi_zero_facebook, mod_map);
}

