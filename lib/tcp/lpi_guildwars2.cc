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


static inline bool match_gw2_req(uint32_t payload, uint32_t len) {

        if (len < 285 || len > 290)
                return false;
        if (MATCH(payload, 0x50, 0x20, 0x2f, 0x53))
                return true;
        return false;

}

static inline bool match_gw2_resp(uint32_t payload, uint32_t len) {

        if (len != 35)
                return false;
        if (MATCH(payload, 0x53, 0x54, 0x53, 0x2f))
                return true;
        return false;

}

static inline bool match_guildwars2(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_gw2_req(data->payload[1], data->payload_len[1])) {
                if (match_gw2_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_gw2_req(data->payload[0], data->payload_len[0])) {
                if (match_gw2_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_guildwars2 = {
	LPI_PROTO_GUILDWARS2,
	LPI_CATEGORY_GAMING,
	"GuildWars2",
	5,
	match_guildwars2
};

void register_guildwars2(LPIModuleMap *mod_map) {
	register_protocol(&lpi_guildwars2, mod_map);
}

