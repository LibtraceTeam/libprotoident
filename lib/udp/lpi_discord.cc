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

/* discord.gg */

static inline bool discord_payload_match(uint32_t a, uint32_t b) {

        uint32_t bytea = (ntohl(a) >> 24);
        uint32_t byteb = (ntohl(b) & 0xff);

        if (bytea == byteb && bytea != 0x00) {
                if (MATCH(a, ANY, 0x00, 0x00, 0x00) &&
                                MATCH(b, 0x00, 0x00, 0x00, ANY)) {
                        return true;
                }
        }

        bytea = (ntohl(a) & 0xff);
        byteb = (ntohl(b) >> 24);

        if (bytea == byteb && bytea != 0x00) {
                if (MATCH(b, ANY, 0x00, 0x00, 0x00) &&
                                MATCH(a, 0x00, 0x00, 0x00, ANY)) {
                        return true;
                }
        }

        return false;

}

static inline bool match_discord(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (!discord_payload_match(data->payload[0], data->payload[1]))
                return false;

        if (data->payload_len[0] != 70 || data->payload_len[1] != 70)
                return false;


	return true;
}

static lpi_module_t lpi_discord = {
	LPI_PROTO_UDP_DISCORD,
	LPI_CATEGORY_VOIP,
	"Discord",
	19,
	match_discord
};

void register_discord(LPIModuleMap *mod_map) {
	register_protocol(&lpi_discord, mod_map);
}

