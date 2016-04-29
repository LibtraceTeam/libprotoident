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
 * $Id: lpi_heroes_generals.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_hg_149(uint32_t payload, uint32_t len) {
        if (len == 149 && MATCHSTR(payload, "\xff\xff\xff\xff"))
                return true;
        return false;

}

static inline bool match_hg_1400(uint32_t payload, uint32_t len) {

        /* MTU could affect this XXX */
        if (len != 1400)
                return false;
        
        /* Bits 5-8 of the first byte are always 0 -- rest is random */
        if ((payload & 0x0000000f) != 0x00000000)
                return false;

        return true;

}

static inline bool match_heroes_generals(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_hg_149(data->payload[0], data->payload_len[0])) {
                if (match_hg_1400(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_hg_149(data->payload[1], data->payload_len[1])) {
                if (match_hg_1400(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_heroes_generals = {
	LPI_PROTO_UDP_HEROES_GENERALS,
	LPI_CATEGORY_GAMING,
	"HeroesAndGenerals",
	20,
	match_heroes_generals
};

void register_heroes_generals(LPIModuleMap *mod_map) {
	register_protocol(&lpi_heroes_generals, mod_map);
}

