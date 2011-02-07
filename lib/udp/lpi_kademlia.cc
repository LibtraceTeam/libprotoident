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

static bool is_kad_e9_payload(uint32_t payload, uint32_t len) {

        /* This seem to be some variant of Kademlia, although I have not
         * been able to figure out which */

        /* All packets begin with e9, while possible second bytes are 
         * 0x55, 0x56, 0x60, 0x61, 0x76, 0x75
         *
         * 0x56 is a response to 0x55
         * 0x61 is a response to 0x60
         * 0x76 is a kind of FIN packet, it also responds to 0x75
         *
         * There are also packets that seem to begin with 0xea 0x75 0x78 0x9c.
         */

        if (MATCH(payload, 0xe9, 0x55, ANY, ANY) && len == 27)
                return true;
        if (MATCH(payload, 0xe9, 0x56, ANY, ANY) && len == 27)
                return true;
        if (MATCH(payload, 0xe9, 0x60, ANY, ANY) && len == 34)
                return true;
        if (MATCH(payload, 0xe9, 0x61, ANY, ANY))
                return true;
        if (MATCH(payload, 0xe9, 0x76, ANY, ANY) && len == 18)
                return true;
        if (MATCH(payload, 0xe9, 0x75, ANY, ANY))
                return true;


        if (MATCH(payload, 0xea, 0x75, 0x78, 0x9c))
                return true;

        return false;

}


static inline bool match_kademlia(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->payload_len[0] == 0 && is_kad_e9_payload(data->payload[1],
                                data->payload_len[1]))
                return true;

        if (data->payload_len[1] == 0 && is_kad_e9_payload(data->payload[0],
                                data->payload_len[0]))
                return true;

        if (is_kad_e9_payload(data->payload[0], data->payload_len[0]) &&
                        is_kad_e9_payload(data->payload[1],
                        data->payload_len[1]))
                return true;


	return false;
}

static lpi_module_t lpi_kademlia = {
	LPI_PROTO_UDP_KADEMLIA,
	LPI_CATEGORY_P2P_STRUCTURE,
	"Kademlia",
	11,
	match_kademlia
};

void register_kademlia(LPIModuleMap *mod_map) {
	register_protocol(&lpi_kademlia, mod_map);
}

