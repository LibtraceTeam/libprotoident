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

static inline bool match_openvpn_handshake(uint32_t payload, uint32_t len) {

        uint16_t pktlen = ntohs((uint16_t)payload);

        /* First two bytes are the length of the packet (not including the
         * length) */
        if (pktlen + 2 != len)
                return false;

        /* Handshake packets have opcodes of either 7 or 8 and key IDs of 
         * zero, so the third byte is either 0x38 or 0x40 */

        /* Ref: http://tinyurl.com/37tt3xe */

        if (MATCH(payload, ANY, ANY, 0x38, ANY))
                return true;
        if (MATCH(payload, ANY, ANY, 0x40, ANY))
                return true;


        return false;

}


static inline bool match_openvpn(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!match_openvpn_handshake(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_openvpn_handshake(data->payload[1], data->payload_len[1]))
                return false;

	return true;
}

static lpi_module_t lpi_openvpn = {
	LPI_PROTO_OPENVPN,
	LPI_CATEGORY_TUNNELLING,
	"OpenVPN",
	3,	/* Most of this rule is based on a length field in the header */
	match_openvpn
};

void register_openvpn(LPIModuleMap *mod_map) {
	register_protocol(&lpi_openvpn, mod_map);
}

