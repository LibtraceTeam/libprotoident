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
 * $Id: lpi_sanandreas_mp.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* Matches the GTA: San Andreas Multiplayer Mod -- http://www.sa-mp.com/ */

static inline bool match_samp_request(uint32_t payload, uint32_t len) {
        if (!MATCHSTR(payload, "SAMP"))
                return false;
        if (len != 71)
                return false;
        return true;

}

static inline bool match_samp_reply(uint32_t payload, uint32_t len) {
        if (len == 0)
                return true;
        if (!MATCHSTR(payload, "SAMP"))
                return false;
        if (len == 11 || len == 15)
                return true;
        return false;
}


static inline bool match_ffs_req(uint32_t payload, uint32_t len) {
        if (len != 4)
                return false;
        if (MATCH(payload, 0x40, 0xb1, 0xd1, 0xef))
                return true;
        return false;
}

static inline bool match_ffs_resp(uint32_t payload, uint32_t len) {
        if (len != 2)
                return false;
        if (MATCH(payload, 0x16, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_sanandreas_mp(lpi_data_t *data, 
                lpi_module_t *mod UNUSED) {

        if (match_samp_request(data->payload[0], data->payload_len[0])) {
                if (match_samp_reply(data->payload[1], data->payload_len[1]))
                        return true;
        }
        
        if (match_samp_request(data->payload[1], data->payload_len[1])) {
                if (match_samp_reply(data->payload[0], data->payload_len[0]))
                        return true;
        }

        /* Traffic seen on port 7777 for a SA-MP server called
         * Fight Fun Server (ff-server.com). */
        if (match_ffs_req(data->payload[1], data->payload_len[1])) {
                if (match_ffs_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_ffs_req(data->payload[0], data->payload_len[0])) {
                if (match_ffs_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_sanandreas_mp = {
	LPI_PROTO_UDP_SANANDREAS,
	LPI_CATEGORY_GAMING,
	"GTA_SanAndreas_Multiplayer",
	8,
	match_sanandreas_mp
};

void register_sanandreas_mp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_sanandreas_mp, mod_map);
}

