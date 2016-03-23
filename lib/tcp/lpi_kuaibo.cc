/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011-2015 The University of Waikato, Hamilton, New Zealand.
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

/* First two bytes are actually a length field, byte 3 is always 0x03,
 * byte 4 is probably a message type (must match both ways).
 *
 * However, since messages of a certain type always seem to have the same
 * length for the request and response, I prefer matching like this
 * where I can enforce the length requirement.
 */

static inline bool match_1c_req(uint32_t payload, uint32_t len) {
        if (len == 28 && MATCH(payload, 0x00, 0x1c, 0x03, 0x03))
                return true;
        return false;
}

static inline bool match_0c_resp(uint32_t payload, uint32_t len) {
        if (len == 12 && MATCH(payload, 0x00, 0x0c, 0x03, 0x03))
                return true;
        return false;
}

static inline bool match_30_req(uint32_t payload, uint32_t len) {

        if (len == 48 && MATCH(payload, 0x00, 0x30, 0x03, 0x06))
                return true;
        return false;

}

static inline bool match_20_resp(uint32_t payload, uint32_t len) {

        if (len == 32 && MATCH(payload, 0x00, 0x20, 0x03, 0x06))
                return true;
        return false;

}

static inline bool match_24_req(uint32_t payload, uint32_t len) {

        if (len == 36 && MATCH(payload, 0x00, 0x24, 0x03, 0x01))
                return true;
        return false;

}

static inline bool match_10_resp(uint32_t payload, uint32_t len) {

        if (len == 16 && MATCH(payload, 0x00, 0x10, 0x03, 0x01))
                return true;
        return false;

}

static inline bool match_kuaibo(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_1c_req(data->payload[0], data->payload_len[0])) {
                if (match_0c_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_1c_req(data->payload[1], data->payload_len[1])) {
                if (match_0c_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_30_req(data->payload[0], data->payload_len[0])) {
                if (match_20_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_30_req(data->payload[1], data->payload_len[1])) {
                if (match_20_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_24_req(data->payload[0], data->payload_len[0])) {
                if (match_10_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_24_req(data->payload[1], data->payload_len[1])) {
                if (match_10_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_kuaibo = {
	LPI_PROTO_KUAIBO,
	LPI_CATEGORY_STREAMING,
	"Kuaibo",
	51,
	match_kuaibo
};

void register_kuaibo(LPIModuleMap *mod_map) {
	register_protocol(&lpi_kuaibo, mod_map);
}

