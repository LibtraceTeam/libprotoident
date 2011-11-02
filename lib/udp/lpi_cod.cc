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

static inline bool match_cod_payload(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;
        if (!MATCH(payload, 0xff, 0xff, 0xff, 0xff))
                return false;
        return true;

}


static inline bool match_callofduty(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!match_cod_payload(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_cod_payload(data->payload[1], data->payload_len[1]))
                return false;

        /* One packet is always 14 or 15 bytes, the other is usually much 
         * larger */
        if (data->payload_len[0] == 14 || data->payload_len[0] == 15) {
                if (data->payload_len[1] == 0)
                        return true;
                if (data->payload_len[1] > 100)
                        return true;
        }

        if (data->payload_len[1] == 14 || data->payload_len[1] == 15) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[0] > 100)
                        return true;
        }

        /* 13 is also observed */
        if (data->payload_len[0] == 13) {
                if (data->payload_len[1] > 880)
                        return true;
        }

        /* Other packet size combos */

        /* 74 seems to be common on port 20800 which is associated with
         * COD:WaW
         */
        if (data->payload_len[0] == 74) {
                if (data->payload_len[1] == 0)
                        return true;
        }

        if (data->payload_len[1] == 74) {
                if (data->payload_len[0] == 0)
                        return true;
        }

        if (data->payload_len[0] == 45) {
                if (data->payload_len[1] == 0)
                        return true;
        }

        if (data->payload_len[1] == 45) {
                if (data->payload_len[0] == 0)
                        return true;
        }

        if (data->payload_len[0] == 53) {
                if (data->payload_len[1] < 30)
                        return false;
                if (data->payload_len[1] > 33)
                        return false;
                return true;
        }
        if (data->payload_len[1] == 53) {
                if (data->payload_len[0] < 30)
                        return false;
                if (data->payload_len[0] > 33)
                        return false;
                return true;
        }

        if (data->payload_len[0] == 16) {
                if (data->payload_len[1] == 18)
                        return true;
                if (data->payload_len[1] == 16)
                        return true;
                if (data->payload_len[1] == 13)
                        return true;
                if (data->payload_len[1] == 0) {
                	return true;
		}
        }

        if (data->payload_len[1] == 16) {
                if (data->payload_len[0] == 18)
                        return true;
                if (data->payload_len[0] == 16)
                        return true;
                if (data->payload_len[0] == 13)
                        return true;
                if (data->payload_len[0] == 0) {
                        return true;
                }
        }

        if (data->payload_len[0] >= 16 && data->payload_len[0] <= 19) {
                if (data->payload_len[1] < 40)
                        return false;
                if (data->payload_len[1] > 44)
                        return false;
                return true;
        }

        if (data->payload_len[1] >= 16 && data->payload_len[1] <= 19) {
                if (data->payload_len[0] < 40)
                        return false;
                if (data->payload_len[0] > 44)
                        return false;
                return true;
        }


	return false;
}

static lpi_module_t lpi_callofduty = {
	LPI_PROTO_UDP_COD,
	LPI_CATEGORY_GAMING,
	"Call_of_Duty",
	6,	/* Must be lower priority than XLSP */
	match_callofduty
};

void register_callofduty(LPIModuleMap *mod_map) {
	register_protocol(&lpi_callofduty, mod_map);
}

