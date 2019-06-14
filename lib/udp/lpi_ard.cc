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

/* Apple Remote Desktop protocol, generally used to remotely manage Macs.
 * Probably shouldn't be seen on the Internet, particularly with the patterns
 * presented here as this was almost certainly a case where a Mac with remote
 * management enabled was being abused into performing an amplification attack.
 *
 * Of course, being Apple, there is no public documentation of this protocol
 * anywhere so it's pretty hard to write rules that cover legitimate uses of
 * this protocol.
 */

static inline bool match_ard_tiny_req(uint32_t payload, uint32_t len) {
        if (len == 5 && MATCH(payload, 0x00, 0x14, 0x00, 0x01)) {
                return true;
        }
        return false;
}

static inline bool match_ard_large_resp(uint32_t payload, uint32_t len) {

        /* Match the case where the client doesn't reply (i.e. participate
         * in the amplification attack).
         */
        if (len == 0) {
                return true;
        }

        /* All my examples were 1006 bytes, but that's just from one
         * specific machine */
        if (len < 1000) {
                return false;
        }

        if ((ntohl(payload) & 0x0000ffff) != len - 4) {
                return false;
        }

        if (MATCH(payload, 0x00, 0x01, ANY, ANY)) {
                return true;
        }

        return false;
}

static inline bool match_ard(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->server_port != 3283 && data->client_port != 3283) {
                return false;
        }

        if (match_ard_tiny_req(data->payload[0], data->payload_len[0])) {
                if (match_ard_large_resp(data->payload[1], data->payload_len[1])) {
                        return true;
                }
        }

        if (match_ard_tiny_req(data->payload[1], data->payload_len[1])) {
                if (match_ard_large_resp(data->payload[0], data->payload_len[0])) {
                        return true;
                }
        }

	return false;
}

static lpi_module_t lpi_ard = {
	LPI_PROTO_UDP_ARD,
	LPI_CATEGORY_REMOTE,
	"ARD",
	20,
	match_ard
};

void register_ard(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ard, mod_map);
}

