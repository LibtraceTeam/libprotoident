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

/* I *think* this is PSN game traffic - it typically appears on UDP port 3658
 * which is commonly used for that but there's no documentation of the
 * protocol anywhere :(
 */
static inline bool match_psn(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->payload_len[0] == 0 &&
                        MATCH(data->payload[1], 0xff, 0x83, 0xff, 0xfe))
                return true;
        if (data->payload_len[1] == 0 &&
                        MATCH(data->payload[0], 0xff, 0x83, 0xff, 0xfe))
                return true;

        if (MATCH(data->payload[0], 0xff, 0x83, 0xff, 0xfe) &&
                        MATCH(data->payload[1],  0xff, 0x83, 0xff, 0xfe))
                return true;

	return false;
}

static lpi_module_t lpi_psn = {
	LPI_PROTO_UDP_PSN,
	LPI_CATEGORY_GAMING,
	"PSN",
	3,
	match_psn
};

void register_psn(LPIModuleMap *mod_map) {
	register_protocol(&lpi_psn, mod_map);
}

