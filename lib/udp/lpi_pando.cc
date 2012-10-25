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

/* This seems to be a Pando thing - I've found libtorrent handshakes within
 * full payload captures of these packets that refer to Pando peer exchange.
 *
 * It may be a wider Bittorrent thing, but I haven't found any evidence to
 * suggest that any clients other than Pando use it */

static inline bool match_pando_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_str_both(data, "\x00\x00\x00\x09", "\x00\x00\x00\x09"))
                return true;

        if (MATCH(data->payload[0], 0x00, 0x00, 0x00, 0x09) &&
                        data->payload_len[1] == 0)
                return true;

        if (MATCH(data->payload[1], 0x00, 0x00, 0x00, 0x09) &&
                        data->payload_len[0] == 0)
                return true;

        /* This is something I've observed going to hosts belonging to
         * Pando */

        if (match_str_both(data, "UDPA", "UDPR"))
                return true;
        if (match_str_both(data, "UDPA", "UDPE"))
                return true;
	

	return false;
}

static lpi_module_t lpi_pando_udp = {
	LPI_PROTO_UDP_PANDO,
	LPI_CATEGORY_P2P,
	"Pando_UDP",
	10,
	match_pando_udp
};

void register_pando_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_pando_udp, mod_map);
}

