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

/* Matches the Opaserv worm that attacks UDP port 137
 * Ref: http://www.usenix.org/events/osdi04/tech/full_papers/singh/singh_html/
 */

static inline bool match_opaserv(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* The recipient does not reply (usually) */
        if (data->payload_len[0] > 0 && data->payload_len[1] > 0)
                return false;

        if (data->server_port != 137 && data->client_port != 137)
                return false;

        if (match_chars_either(data, 0x01, 0x00, 0x00, 0x10))
                return true;
	

	return false;
}

static lpi_module_t lpi_opaserv = {
	LPI_PROTO_UDP_OPASERV,
	LPI_CATEGORY_MALWARE,
	"Opaserv",
	10,
	match_opaserv
};

void register_opaserv(LPIModuleMap *mod_map) {
	register_protocol(&lpi_opaserv, mod_map);
}

