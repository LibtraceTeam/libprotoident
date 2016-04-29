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
 * $Id: lpi_llp2p.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* Low Latency P2P -- open-source Chinese P2P streaming software.
 * https://github.com/momomou/llp2p
 */
static inline bool match_llp2p_get(uint32_t payload, uint32_t len) {
        /* Outgoing request looks like an HTTP GET -- maybe aiming to fool
         * DPI software? */

        /* Only seen len=133 so far but this seems like it could change */
        if (MATCH(payload, 'G', 'E', 'T', 0x20))
                return true;
        return false;

}

static inline bool match_llp2p_update(uint32_t payload, uint32_t len) {

        /* Not sure on the length requirement, but I've only seen 454
         * bytes so far.
         */
        if (MATCH(payload, 0x13, 0x00, 0x01, 0x00) && len == 454)
                return true;
        return false;

}

static inline bool match_llp2p(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_llp2p_get(data->payload[0], data->payload_len[0])) {
                if (match_llp2p_update(data->payload[1], data->payload_len[1]))
                        return true;
        }
        
        if (match_llp2p_get(data->payload[1], data->payload_len[1])) {
                if (match_llp2p_update(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_llp2p = {
	LPI_PROTO_LLP2P,
	LPI_CATEGORY_P2PTV,
	"LLP2P",
	12,
	match_llp2p
};

void register_llp2p(LPIModuleMap *mod_map) {
	register_protocol(&lpi_llp2p, mod_map);
}

