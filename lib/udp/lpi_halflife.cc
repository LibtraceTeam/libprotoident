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

static inline bool match_halflife_ports(lpi_data_t *data) {
        if (data->server_port >= 27000 && data->server_port < 28000)
                return true;
        if (data->client_port >= 27000 && data->client_port < 28000)
                return true;
        return false;
}

static inline bool match_halflife_nine(uint32_t payload, uint32_t len) {

        if (len != 9)
                return false;
        if (!MATCHSTR(payload,  "\xff\xff\xff\xff"))
                return false;
        return true;

}

static inline bool match_halflife_generic(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;
        if (!MATCHSTR(payload,  "\xff\xff\xff\xff"))
                return false;
        return true;

}

static inline bool match_halflife(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_halflife_nine(data->payload[0], data->payload_len[0])) {
                if (match_halflife_nine(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (!match_halflife_ports(data))
                return false;

        if (match_halflife_generic(data->payload[0], data->payload_len[0])) {
                if (match_halflife_generic(data->payload[1], data->payload_len[1]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_halflife = {
	LPI_PROTO_UDP_HL,
	LPI_CATEGORY_GAMING,
	"HalfLife",
	20,     /* Make sure this comes after other similar game protocols,
                 * e.g. ARMA, Quake */
	match_halflife
};

void register_halflife(LPIModuleMap *mod_map) {
	register_protocol(&lpi_halflife, mod_map);
}

