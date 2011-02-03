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

/* Rules adapted from l7-filter */
static inline bool match_telnet_pattern(uint32_t payload, uint32_t len) {

        /* Sadly we cannot use a simple MATCH, because we're looking for
         * two 0xff characters, which happens to be the same value as ANY.
         */

        if (len >= 4) {
                if ((payload & 0xff0000ff) != (0xff0000ff))
                        return false;
        }
        else if (len == 3) {
                if ((payload & 0xff000000) != (0xff000000))
                        return false;
        }
        else
                return false;

        if (MATCH(payload, ANY, 0xfb, ANY, ANY))
                return true;
        if (MATCH(payload, ANY, 0xfc, ANY, ANY))
                return true;
        if (MATCH(payload, ANY, 0xfd, ANY, ANY))
                return true;
        if (MATCH(payload, ANY, 0xfe, ANY, ANY))
                return true;

        return false;
}


static inline bool match_telnet(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_telnet_pattern(data->payload[0], data->payload_len[0]))
                return true;
        if (match_telnet_pattern(data->payload[1], data->payload_len[1]))
                return true;

	return false;
}

static lpi_module_t lpi_telnet = {
	LPI_PROTO_TELNET,
	LPI_CATEGORY_REMOTE,
	"Telnet", 
	2,
	match_telnet
};

void register_telnet(LPIModuleMap *mod_map) {
	register_protocol(&lpi_telnet, mod_map);
}

