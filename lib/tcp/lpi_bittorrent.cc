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

static inline bool match_bittorrent_header(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;

        if (MATCH(payload, 0x13, 'B', 'i', 't'))
                return true;

        if (len == 3 && MATCH(payload, 0x13, 'B', 'i', 0x00))
                return true;
        if (len == 2 && MATCH(payload, 0x13, 'B', 0x00, 0x00))
                return true;
        if (len == 1 && MATCH(payload, 0x13, 0x00, 0x00, 0x00))
                return true;

        return false;

}


static inline bool match_ww_xx_header(uint32_t payload, uint32_t len) {
        /* Fairly confident that this is related to Bittorrent, though I
         * can't seem to find any source code or documentation that references
         * it.
         *
         * The full string included in the header is:
         * 0x13 #WW-XX#@77
         */
       if (len == 0)
               return true;
       if (MATCH(payload, 0x13, 0x23, 0x57, 0x57))
               return true;
       return false;

}

static inline bool match_bittorrent(lpi_data_t *data, lpi_module_t *mod UNUSED) 
{
        if (match_bittorrent_header(data->payload[0], data->payload_len[0])) {
                if (match_bittorrent_header(data->payload[1], 
                                data->payload_len[1]))
                        return true;
        }

        if (match_ww_xx_header(data->payload[0], data->payload_len[0])) {
                if (match_ww_xx_header(data->payload[1], data->payload_len[1]))
                        return true;
        }

        return false;
}

static lpi_module_t lpi_bittorrent = {
	LPI_PROTO_BITTORRENT,
	LPI_CATEGORY_P2P,
	"BitTorrent",
	2,
	match_bittorrent
};

void register_bittorrent(LPIModuleMap *mod_map) {
	register_protocol(&lpi_bittorrent, mod_map);
}

