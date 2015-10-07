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

static inline bool match_kazaa(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* 0x27 is a ping, 0x28 and 0x29 are pongs */

        /* A Kazaa ping is usually 12 bytes, 0x28 pong is 17, 0x29 pong is 21 */

        if (match_str_both(data, "\x27\x00\x00\x00", "\x28\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x27\x00\x00\x00", "\x29\x00\x00\x00"))
                return true;

        if (match_str_either(data, "\x27\x00\x00\x00")) {
                if (data->payload_len[0] == 0 && data->payload_len[1] == 12)
                        return true;
                if (data->payload_len[1] == 0 && data->payload_len[0] == 12)
                        return true;
        }

	return false;
}

static lpi_module_t lpi_kazaa = {
	LPI_PROTO_UDP_KAZAA,
	LPI_CATEGORY_P2P,
	"Kazaa_UDP",
	4,
	match_kazaa
};

void register_kazaa(LPIModuleMap *mod_map) {
	register_protocol(&lpi_kazaa, mod_map);
}

