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

static inline bool match_xlsp_payload(uint32_t payload, uint32_t len,
                uint32_t other_len, lpi_data_t *data) {

        /* This is almost all based on observing traffic on port 3074. Not
         * very scientific, but seems more or less right */



        /* We've only ever seen a few of the packet sizes in one-way flows,
         * so let's not match any of the others if there is no response */
        if (MATCH(payload, 0x00, 0x00, 0x00, 0x00)) {
                if (len == 139)
                        return true;
                if (len == 122)
                        return true;
                if (len == 156)
                        return true;
                if (len == 82)
                        return true;
                if (len == 50)
                        return true;
                if (len == 83)
                        return true;
                if (len == 43)
                        return true;
                if (len == 75)
                        return true;
                if (len == 120 && other_len != 0)
                        return true;
                if (len == 91 && other_len != 0)
                        return true;
                if (len == 0 && other_len != 0)
                        return true;
                if (len == 90 && other_len == 138)
                        return true;
                if (len == 138 && other_len == 90)
                        return true;

        }

        if (len == 24) {
		/* Employ port number restriction because these rules are weak
		 */
		if (data->server_port != 3074 && data->client_port != 3074)
			return false;
                if (MATCH(payload, 0x0d, ANY, ANY, ANY))
                        return true;
                if (MATCH(payload, 0x80, ANY, ANY, ANY))
                        return true;

        }

        if (len == 29) {
                if (MATCH(payload, 0x0c, 0x02, 0x00, ANY))
                        return true;
                if (MATCH(payload, 0x0b, 0x02, 0x00, ANY))
                        return true;
                if (MATCH(payload, 0x0e, 0x02, 0x00, ANY))
                        return true;
        }


        return false;

}


static inline bool match_xlsp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Had a few false matches against DNS traffic in the past, so
	 * rule out port 53 traffic */
	if (data->server_port == 53 || data->client_port == 53)
		return false;

        /* Commonly observed request/response pattern */
        if (match_chars_either(data, 0x0d, 0x02, 0x00, ANY)) {
                if (data->payload_len[0] == 0 && data->payload_len[1] == 29)
                        return true;
                if (data->payload_len[1] == 0 && data->payload_len[0] == 29)
                        return true;
                if (data->payload_len[0] != 29 || data->payload_len[1] != 29)
                        return false;
                if (match_chars_either(data, 0x0c, 0x02, 0x00, ANY))
                        return true;
                if (MATCH(data->payload[0], 0x0d, 0x02, 0x00, ANY) &&
                                MATCH(data->payload[1], 0x0d, 0x02, 0x00, ANY))
                        return true;
                return false;
        }

        /* Unlike other combos, 1336 and 287 (or rarely 286) only go with
         * each other 
         *
         * 1011 (or rarely 1010) is also a possible response */
        if (match_str_both(data, "\x00\x00\x00\x00", "\x00\x00\x00\x00")) {
                if (data->payload_len[0] == 1336) {
                        if (data->payload_len[1] == 287)
                                return true;
                        if (data->payload_len[1] == 1011)
                                return true;
                        if (data->payload_len[1] == 286)
                                return true;
                        if (data->payload_len[1] == 1010)
                                return true;
                        if (data->payload_len[1] == 1003)
                                return true;
                }
                if (data->payload_len[1] == 1336) {
                        if (data->payload_len[0] == 287)
                                return true;
                        if (data->payload_len[0] == 1011)
                                return true;
                        if (data->payload_len[0] == 286)
                                return true;
                        if (data->payload_len[0] == 1010)
                                return true;
                        if (data->payload_len[0] == 1003)
                                return true;
                }

                /* This is something to do with PunkBuster? */
                if (data->payload_len[0] == 4) {
                        if (data->payload_len[1] == 4)
                                return true;
                }
                if (data->payload_len[1] == 4) {
                        if (data->payload_len[0] == 4)
                                return true;
                }
        }


        /* Enforce port 3074 being involved, to reduce false positive rate for
         * one-way transactions */

        if (match_str_either(data, "\xff\xff\xff\xff")) {
                if (data->server_port != 3074 && data->client_port != 3074)
                        return false;
                if (data->payload_len[0] == 14 && data->payload_len[1] == 0)
                        return true;
                if (data->payload_len[1] == 14 && data->payload_len[0] == 0)
                        return true;
        }

        /* We could also enforce the port number here too, but we still see a 
         * lot of one-way traffic that matches these rules on other ports.
         * I'm pretty confident it is XLSP, but this should be watched
         * closely to make sure it isn't overmatching */

        if (!match_xlsp_payload(data->payload[0], data->payload_len[0],
                        data->payload_len[1], data))
                return false;
        if (!match_xlsp_payload(data->payload[1], data->payload_len[1],
                        data->payload_len[0], data))
                return false;

        return true;

}


static lpi_module_t lpi_xlsp = {
	LPI_PROTO_UDP_XLSP,
	LPI_CATEGORY_GAMING,
	"XboxLive_UDP",
	6,
	match_xlsp
};

void register_xlsp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_xlsp, mod_map);
}

