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


/* Appears to be H1Z1, an early access MMO (DayZ clone) from Sony Online */

static inline bool match_h1z1_req1(uint32_t payload, uint32_t len) {

        if (len == 25 && MATCH(payload, 0x00, 0x01, 0x00, 0x00))
                return true;
        return false;

}

static inline bool match_h1z1_resp1(uint32_t payload, uint32_t len) {

        if (len == 21 && MATCH(payload, 0x00, 0x02, ANY, ANY))
                return true;
        return false;

}

static inline bool match_h1z1_req2(uint32_t payload, uint32_t len) {

        if (len == 35 && MATCH(payload, 0x00, 0x01, 0x00, 0x00))
                return true;
        return false;

}

static inline bool match_h1z1_resp2(uint32_t payload, uint32_t len) {

        if (len == 6 && MATCH(payload, 0x00, 0x15, ANY, ANY))
                return true;
        return false;

}


static inline bool match_h1z1(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* There are a couple of request / response patterns */

        if (match_h1z1_req1(data->payload[1], data->payload_len[1])) {
                if (match_h1z1_resp1(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_h1z1_req1(data->payload[0], data->payload_len[0])) {
                if (match_h1z1_resp1(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_h1z1_req2(data->payload[1], data->payload_len[1])) {
                if (match_h1z1_resp2(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_h1z1_req2(data->payload[0], data->payload_len[0])) {
                if (match_h1z1_resp2(data->payload[1], data->payload_len[1]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_h1z1 = {
	LPI_PROTO_UDP_H1Z1,
	LPI_CATEGORY_GAMING,
	"H1Z1",
	25,
	match_h1z1
};

void register_h1z1(LPIModuleMap *mod_map) {
	register_protocol(&lpi_h1z1, mod_map);
}

