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
 * $Id: lpi_trion.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* Trion - publisher of F2P online games e.g. Archeage, Trove, etc.
 * 
 * For now, I'm just going to group all Trion's games into a single "protocol"
 * as I doubt there is much need to make a distinction.
 */

/* This is probably a length field */
static inline bool match_trion_29(uint32_t payload, uint32_t len) {
        if (len != 29)
                return false;
        if (!MATCH(payload, 0x18, 0x00, 0x00, 0x00))
                return false;
        return true;

}

/* This is probably a length field */
static inline bool match_trion_23(uint32_t payload, uint32_t len) {
        if (len != 23)
                return false;
        if (!MATCH(payload, 0x12, 0x00, 0x00, 0x00))
                return false;
        return true;

}

static inline bool match_trion_1c(uint32_t payload, uint32_t len) {
        if (len == 263 && MATCH(payload, 0x1c, 0x80, 0x20, 0x00))
                return true;
        return false;
}

static inline bool match_trion_2080(uint32_t payload, uint32_t len) {
        if (len == 263 && MATCH(payload, 0x20, 0x80, 0x20, 0x00))
                return true;
        return false;
}

static inline bool match_trion(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* We can also try to limit to port 6560 and 37000-37100, if
         * necessary */

        if (match_trion_29(data->payload[0], data->payload_len[0])) {
                if (match_trion_23(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_trion_29(data->payload[1], data->payload_len[1])) {
                if (match_trion_23(data->payload[0], data->payload_len[0]))
                        return true;
        }

        /* RIFT and Defiance require TCP port 6540 and 50000 and use a
         * different payload pattern */
        if (match_trion_1c(data->payload[0], data->payload_len[0])) {
                if (match_trion_2080(data->payload[1], data->payload_len[1])) 
                        return true;
        }

        if (match_trion_1c(data->payload[1], data->payload_len[1])) {
                if (match_trion_2080(data->payload[0], data->payload_len[0])) 
                        return true;
        }

	return false;
}

static lpi_module_t lpi_trion = {
	LPI_PROTO_TRION,
	LPI_CATEGORY_GAMING,
	"TrionGames",
	8,
	match_trion
};

void register_trion(LPIModuleMap *mod_map) {
	register_protocol(&lpi_trion, mod_map);
}

