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
 * $Id: lpi_dota2.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* DOTA 2 -- a popular multiplayer battleground game */

static inline bool match_dota2_20(uint32_t payload, uint32_t len) {

        if (len != 20)
                return false;
        if (MATCHSTR(payload, "\xff\xff\xff\xff"))
                return true;
        return false;

}

static inline bool match_dota2_30(uint32_t payload, uint32_t len) {

        if (len != 30)
                return false;
        if (MATCHSTR(payload, "\xff\xff\xff\xff"))
                return true;
        return false;

}

static inline bool match_dota2_0100(uint32_t payload, uint32_t len) {

        if (len != 216)
                return false;
        if (MATCH(payload, 0x01, 0x00, 0x73, 0x64))
                return true;
        return false;

}

static inline bool match_dota2_0212(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0x02, 0x12, ANY, ANY))
                return true;
        return false;
}


static inline bool match_dota2(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_dota2_20(data->payload[0], data->payload_len[0])) {
                if (match_dota2_30(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_dota2_20(data->payload[1], data->payload_len[1])) {
                if (match_dota2_30(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_dota2_0100(data->payload[0], data->payload_len[0])) {
                if (match_dota2_0212(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_dota2_0100(data->payload[1], data->payload_len[1])) {
                if (match_dota2_0212(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_dota2 = {
	LPI_PROTO_UDP_DOTA2,
	LPI_CATEGORY_GAMING,
	"DOTA2",
	10,
	match_dota2
};

void register_dota2(LPIModuleMap *mod_map) {
	register_protocol(&lpi_dota2, mod_map);
}

