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

static inline bool match_unreal_query(uint32_t payload, uint32_t len) {

        /* UT2004 retail is 0x80, demo is 0x7f */

        /* Queries are 5 bytes */
        if (len != 5)
                return false;
        if (MATCH(payload, 0x80, 0x00, 0x00, 0x00))
                return true;
        if (MATCH(payload, 0x7f, 0x00, 0x00, 0x00))
                return true;
        return false;

}


static inline bool match_unreal(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* http://www.unrealadmin.org/forums/showthread.php?p=56944 */

        if (match_unreal_query(data->payload[0], data->payload_len[0])) {
                if (MATCH(data->payload[1], 0x80, 0x00, 0x00, 0x00))
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }

        if (match_unreal_query(data->payload[1], data->payload_len[1])) {
                if (MATCH(data->payload[0], 0x80, 0x00, 0x00, 0x00))
                        return true;
                if (data->payload_len[0] == 0)
                        return true;
        }


	return false;
}

static lpi_module_t lpi_unreal = {
	LPI_PROTO_UDP_UNREAL,
	LPI_CATEGORY_GAMING,
	"Unreal",
	5,
	match_unreal
};

void register_unreal(LPIModuleMap *mod_map) {
	register_protocol(&lpi_unreal, mod_map);
}

