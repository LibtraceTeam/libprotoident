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

/** XXX This module is currently disabled due to a tendency to overmatch! */

static inline bool match_mystery_emule(lpi_data_t *data, lpi_module_t *mod UNUSED) {
        /* These particular patterns occur frequently on port 4672, making
         * me think they're some sort of emule traffic but there is no
         * obvious documentation. The payloads appear to be random, which
         * is unlike all other emule traffic. The flows tend to consist of
         * only one or two packets in each direction.
	 *
	 * XXX Comparison with DPI tools suggest that this is indeed eMule!
	 *
         */

        if (data->payload_len[0] == 44 && data->payload_len[1] >= 38 &&
                        data->payload_len[1] <= 50)
                return true;
        if (data->payload_len[1] == 44 && data->payload_len[0] >= 38 &&
                        data->payload_len[0] <= 50)
                return true;

        if (data->payload_len[0] == 51 && (data->payload_len[1] == 135 ||
                        data->payload_len[1] == 85 ||
                        data->payload_len[1] == 310))
                return true;
        if (data->payload_len[1] == 51 && (data->payload_len[0] == 135 ||
                        data->payload_len[0] == 85 ||
                        data->payload_len[0] == 310))
                return true;


        return false;
}


static inline bool match_emule_weak_udp(lpi_data_t *data, 
		lpi_module_t *mod UNUSED) {

	/* This covers a particular branch of emule traffic which is harder
	 * to reliably detect than even regular emule (which isn't great to
	 * begin with).
	 */

	if (match_mystery_emule(data, NULL))
		return true;

	return false;
}

static lpi_module_t lpi_emule_weak_udp = {
	LPI_PROTO_UDP_EMULE,
	LPI_CATEGORY_P2P,
	"eMule_UDP",
	20,
	match_emule_weak_udp
};

void register_emule_weak_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_emule_weak_udp, mod_map);
}

