/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011 The University of Waikato, Hamilton, New Zealand.
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

static inline bool match_gamespy(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_str_either(data, "\\sta"))
                return true;
        if (match_str_either(data, "\\inf"))
                return true;
        if (match_str_either(data, "\\gam"))
                return true;
        if (match_str_either(data, "\\hos"))
                return true;
        if (match_str_either(data, "\\bas"))
                return true;

        /* Gamespy request begins with 0xfe 0xfd FOO BAR. The response begins
         * with FOO BAR, where FOO and BAR are specific bytes */

        if (MATCH(data->payload[0], 0xfe, 0xfd, ANY, ANY) &&
                ((data->payload[1] << 16) == (data->payload[0] & 0xffff0000)))
                return true;
        if (MATCH(data->payload[1], 0xfe, 0xfd, ANY, ANY) &&
                ((data->payload[0] << 16) == (data->payload[1] & 0xffff0000)))
                return true;

        /* These packets have also been observed between gamespy servers
         * and for gamespy-powered games, e.g. GTA 4 */
        if (match_str_both(data, "\xfd\xfc\x1e\x66", "\xfd\xfc\x1e\x66"))
                return true;

        if (match_str_either(data, "\xfd\xfc\x1e\x66")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }


	return false;
}

static lpi_module_t lpi_gamespy = {
	LPI_PROTO_UDP_GAMESPY,
	LPI_CATEGORY_GAMING,
	"GameSpy",
	3,
	match_gamespy
};

void register_gamespy(LPIModuleMap *mod_map) {
	register_protocol(&lpi_gamespy, mod_map);
}

