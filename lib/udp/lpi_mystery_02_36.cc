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

static inline bool match_mystery_02_36(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Another mystery protocol :/
         *
         * Characterised by 36 byte datagrams in both directions, always
         * beginning with 02 00 XX 00.
         *
         * Later packets also begin with 02 and have 00 in the fourth byte.
         * Packet size varies.
         */

        if (MATCH(data->payload[0], 0x02, 0x00, ANY, ANY) &&
                        data->payload_len[0] == 36) {
                if (data->payload_len[1] == 0)
                        return true;
                if (MATCH(data->payload[1], 0x02, 0x00, ANY, ANY) &&
                                data->payload_len[1] == 36)
                        return true;
        }

        if (MATCH(data->payload[1], 0x02, 0x00, ANY, ANY) &&
                        data->payload_len[1] == 36) {
                if (data->payload_len[0] == 0)
                        return true;
                if (MATCH(data->payload[0], 0x02, 0x00, ANY, ANY) &&
                                data->payload_len[0] == 36)
                        return true;
        }

	return false;
}

static lpi_module_t lpi_mystery_02_36 = {
	LPI_PROTO_UDP_MYSTERY_02_36,
	LPI_CATEGORY_NO_CATEGORY,
	"Mystery_02_36",
	250,
	match_mystery_02_36
};

void register_mystery_02_36(LPIModuleMap *mod_map) {
	register_protocol(&lpi_mystery_02_36, mod_map);
}

