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

static inline bool match_invalid_bittorrent(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* This function will match anyone doing bittorrent in one
         * direction and *something else* in the other.
         *
         * I've broken it down into several separate conditions, just in case
         * we want to treat them as separate instances later on */



        /* People trying to do Bittorrent to an actual HTTP server, rather than
         * someone peering on port 80 */
        if (match_str_either(data, "HTTP") &&
                        match_chars_either(data, 0x13, 'B', 'i', 't'))
                return true;

        /* People sending GETs to a Bittorrent peer?? */
        if (match_str_either(data, "GET ") &&
                        match_chars_either(data, 0x13, 'B', 'i', 't'))
                return true;

        /* We also get a bunch of cases where one end is doing bittorrent
         * and the other end is speaking a protocol that begins with a 4
         * byte length field. */
        if (match_chars_either(data, 0x13, 'B', 'i', 't')) {
                if (match_payload_length(data->payload[0],data->payload_len[0]))
                        return true;
                if (match_payload_length(data->payload[1],data->payload_len[1]))
                        return true;
        }


        /* This assumes we've checked for regular bittorrent prior to calling
         * this function! */
        if (match_chars_either(data, 0x13, 'B', 'i', 't'))
                return true;


	return false;
}

static lpi_module_t lpi_invalid_bittorrent = {
	LPI_PROTO_INVALID_BT,
	LPI_CATEGORY_MIXED,
	"Invalid_Bittorrent",
	200,
	match_invalid_bittorrent
};

void register_invalid_bittorrent(LPIModuleMap *mod_map) {
	register_protocol(&lpi_invalid_bittorrent, mod_map);
}

