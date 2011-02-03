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

static inline bool match_emule(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Check that payload begins with e3 or c5 in both directions before 
         * classifying as eMule */
        /* (I noticed that most emule(probably) flows began with "e3 xx 00 00" 
         * or "c5 xx 00 00", perhaps is worth looking into... Although I 
         * couldn't find anything about emule packets) */

        if (data->payload_len[0] < 4 && data->payload_len[1] < 4)
                return false;

        if (MATCH(data->payload[0], 0xe3, ANY, 0x00, 0x00) &&
            MATCH(data->payload[1], 0xe3, ANY, 0x00, 0x00))
                return true;

        if (MATCH(data->payload[0], 0xe3, ANY, 0x00, 0x00) &&
            MATCH(data->payload[1], 0xc5, ANY, 0x00, 0x00))
                return true;

        /* XXX I haven't seen any obviously legit emule that starts with c5
         * in both directions */
        /*
        if (MATCH(data->payload[0], 0xc5, ANY, ANY, ANY) &&
            MATCH(data->payload[1], 0xc5, ANY, ANY, ANY))
                return true;
        */

        if (MATCH(data->payload[0], 0xc5, ANY, 0x00, 0x00) &&
            MATCH(data->payload[1], 0xe3, ANY, 0x00, 0x00))
                return true;

        if (MATCH(data->payload[0], 0xe3, ANY, 0x00, 0x00) &&
                data->payload_len[1] == 0)
                return true;

        if (MATCH(data->payload[1], 0xe3, ANY, 0x00, 0x00) &&
                data->payload_len[0] == 0)
                return true;

	

	return false;
}

static lpi_module_t lpi_emule = {
	LPI_PROTO_EMULE,
	LPI_CATEGORY_P2P,
	"EMule",
	10,	/* We've always had this at low priority */
	match_emule
};

void register_emule(LPIModuleMap *mod_map) {
	register_protocol(&lpi_emule, mod_map);
}

