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

static inline bool match_rtp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_chars_either(data, 0x80, 0x80, ANY, ANY) &&
                        match_str_either(data, "\x00\x01\x00\x08"))
                return true;

	/* All two-way traffic must match the above rule */
	if (data->payload_len[0] != 0 && data->payload_len[1] != 0)
		return false;

	/* Watch out for one-way DNS... */
	if (data->client_port == 53 || data->client_port == 53)
		return false;

        /* 96 and 97 are the first two dynamic payload types */
        if (match_chars_either(data, 0x80, 0x60, ANY, ANY))
                return true;
        if (match_chars_either(data, 0x80, 0x61, ANY, ANY)) 
                return true;


        /* If the MSB in the second byte is set, this is a "marker" packet */
        if (match_chars_either(data, 0x80, 0xe0, ANY, ANY))
                return true;
        if (match_chars_either(data, 0x80, 0xe1, ANY, ANY))
                return true;


	return false;
}

static lpi_module_t lpi_rtp = {
	LPI_PROTO_UDP_RTP,
	LPI_CATEGORY_VOIP,
	"RTP",
	3,
	match_rtp
};

void register_rtp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_rtp, mod_map);
}

