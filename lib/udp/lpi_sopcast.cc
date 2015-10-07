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

static inline bool match_sopcast_req(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0xff, 0xff, 0x01, ANY)) {
                if (len == 52)
                        return true;
        }

        return false;
}

static inline bool match_sopcast_reply(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x00, ANY, 0x02, ANY)) {
                if (len == 80)
                        return true;
        }
        if (MATCH(payload, 0x00, ANY, 0x01, ANY)) {
                if (len == 60)
                        return true;
        }

        return false;
}


static inline bool match_sopcast(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if ((data->payload[0] & 0xff000000) != (data->payload[1] & 0xff000000))
                return false;

        if (match_sopcast_req(data->payload[0], data->payload_len[0])) {
                if (match_sopcast_reply(data->payload[1], data->payload_len[1]))
                        return true;
                if (match_sopcast_req(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_sopcast_req(data->payload[1], data->payload_len[1])) {
                if (match_sopcast_reply(data->payload[0], data->payload_len[0]))
                        return true;
                if (match_sopcast_req(data->payload[0], data->payload_len[0]))
                        return true;
        }
	

	return false;
}

static lpi_module_t lpi_sopcast = {
	LPI_PROTO_UDP_SOPCAST,
	LPI_CATEGORY_P2PTV,
	"Sopcast",
	5,
	match_sopcast
};

void register_sopcast(LPIModuleMap *mod_map) {
	register_protocol(&lpi_sopcast, mod_map);
}

