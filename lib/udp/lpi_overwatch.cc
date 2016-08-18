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

/* Not 100% confirmed, mainly because there is no trial or F2P version of
 * Overwatch to test against. Would be great if anyone out there who owns
 * Overwatch to confirm this for me :)
 */

static inline bool match_owatch_cc(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0xcc, 0x8e, 0x5f, 0x0d))
                return true;
        return false;
}

static inline bool match_owatch_df(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;

        if ((ntohl(payload) & 0xfffff000) == 0xdffcf000)
                return true;
        return false;

}

static inline bool match_overwatch(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_owatch_cc(data->payload[0], data->payload_len[0])) {
                if (match_owatch_df(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_owatch_cc(data->payload[1], data->payload_len[1])) {
                if (match_owatch_df(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_overwatch = {
	LPI_PROTO_UDP_OVERWATCH,
	LPI_CATEGORY_GAMING,
	"Overwatch",
	12,
	match_overwatch
};

void register_overwatch(LPIModuleMap *mod_map) {
	register_protocol(&lpi_overwatch, mod_map);
}

