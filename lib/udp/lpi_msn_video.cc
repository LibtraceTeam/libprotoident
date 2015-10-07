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

static inline bool match_msn_video(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	 /* The authorization messages use a code of 0x48, followed by 3
         * bytes of zero. The packet contains no non-header payload, so the
         * payload length must be the size of the MSN video header (10 bytes)
         *
         * Ref: http://ml20rc.msnfanatic.com/vc_1_1/index.html
         */
        if (!(MATCHSTR(data->payload[0], "\x48\x00\x00\x00") &&
                        data->payload_len[0] == 10))
                return false;

        if (!(MATCHSTR(data->payload[1], "\x48\x00\x00\x00") &&
                        data->payload_len[1] == 10))
                return false;

        return true;
	
}

static lpi_module_t lpi_msn_video = {
	LPI_PROTO_UDP_MSN_VIDEO,
	LPI_CATEGORY_CHAT,
	"MSN_Video_UDP",
	3,
	match_msn_video
};

void register_msn_video(LPIModuleMap *mod_map) {
	register_protocol(&lpi_msn_video, mod_map);
}

