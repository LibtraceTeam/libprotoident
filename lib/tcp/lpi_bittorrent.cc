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


static inline bool match_bittorrent(lpi_data_t *data, lpi_module_t *mod UNUSED) 
{
        if (!match_bittorrent_header(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_bittorrent_header(data->payload[1], data->payload_len[1]))
                return false;
        return true;
}

extern "C"
lpi_module_t * lpi_register() {
	
	lpi_module_t *mod = new lpi_module_t;

	mod->protocol = LPI_PROTO_BITTORRENT;
	strncpy(mod->name, "Bittorrent", 255);
	mod->category = LPI_CATEGORY_P2P;
	mod->priority = 2; 	
	mod->dlhandle = NULL;
	mod->lpi_callback = match_bittorrent;

	return mod;

}
