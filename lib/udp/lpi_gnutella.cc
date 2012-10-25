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

static inline bool match_gnutella_maint(lpi_data_t *data) {


        /* All Gnutella UDP communications begin with a random 16 byte
         * message ID - the request and the response must have the same
         * message ID */

        /* OK, for now I'm going to just work with two-way exchanges, because
         * one-way is going to be pretty unreliable :( */

        /* One exception! Unanswered PINGs */
        if (data->payload_len[0] == 23 && data->payload_len[1] == 0)
                return true;
        if (data->payload_len[1] == 23 && data->payload_len[0] == 0)
                return true;

        if (data->payload_len[1] == 0 || data->payload_len[0] == 0)
                return false;

        /* There seem to be some message types that do weird stuff with the
         * GUID - I suspect they are Limewire extensions. */

        if (data->payload_len[0] == 23 && data->payload_len[1] == 23) {
                if (match_chars_either(data, 0x00, 0x00, 0x00, 0x00))
                        return true;
        }

        /* If there is payload in both directions, the message IDs must match */
        if (data->payload[0] != data->payload[1])
                return false;


        /* All of these payload combinations are based purely on transactions
         * observed on UDP port 6346 (a known Gnutella port) - sadly, there's
         * no genuinely good documentation on the typical size of Gnutella
         * UDP requests */

        /* PING */
        if (data->payload_len[0] == 23 && data->payload_len[1] < 100)
                return true;
        if (data->payload_len[1] == 23 && data->payload_len[0] < 100)
                return true;

        /* 727 byte packets are matched with 81 or 86 byte packets */
        if (data->payload_len[0] == 727 && (data->payload_len[1] == 81 ||
                        data->payload_len[1] == 86))
                return true;
        if (data->payload_len[1] == 727 && (data->payload_len[0] == 81 ||
                        data->payload_len[0] == 86))
		return true;

        /* 72 and (61 or 81 or 86) byte packets seem to go together */
        if (data->payload_len[0] == 72) {
                if (data->payload_len[1] == 61)
                        return true;
                if (data->payload_len[1] == 81)
                        return true;
                if (data->payload_len[1] == 86)
                        return true;
        }

        if (data->payload_len[1] == 72) {
                if (data->payload_len[0] == 61)
                        return true;
                if (data->payload_len[0] == 81)
                        return true;
                if (data->payload_len[0] == 86)
                        return true;
        }

        /* 81 and 544 */
        if (data->payload_len[0] == 81 && data->payload_len[1] == 544)
                return true;
        if (data->payload_len[1] == 81 && data->payload_len[0] == 544)
                return true;

        /* 55 and 47 */
        if (data->payload_len[0] == 55 && data->payload_len[1] == 47)
                return true;
        if (data->payload_len[1] == 55 && data->payload_len[0] == 47)
                return true;

        /* 38 and 96 */
        if (data->payload_len[0] == 38 && data->payload_len[1] == 96)
                return true;
        if (data->payload_len[1] == 38 && data->payload_len[0] == 96)
                return true;

        /* 67 and (81 or 86) */
        if (data->payload_len[0] == 67 && (data->payload_len[1] == 81 ||
                        data->payload_len[1] == 86))
                return true;
        if (data->payload_len[1] == 67 && (data->payload_len[0] == 81 ||
                        data->payload_len[0] == 86))
                return true;


        /* Responses to 35 byte requests range between 136 and 180 bytes */
        if (data->payload_len[0] == 35 && (data->payload_len[1] <= 180 &&
                        data->payload_len[1] >= 136))
                return true;
        if (data->payload_len[1] == 35 && (data->payload_len[0] <= 180 &&
                        data->payload_len[0] >= 136))
                return true;

        /* 29 byte requests seem to be met with 80-100 byte responses OR
         * a 46 byte response */
        if (data->payload_len[0] == 29) {
                if (data->payload_len[1] <= 100 && data->payload_len[1] >= 80)
                        return true;
                if (data->payload_len[1] == 46)
                        return true;
        }
        if (data->payload_len[1] == 29) {
                if (data->payload_len[0] <= 100 && data->payload_len[0] >= 80)
                        return true;
                if (data->payload_len[0] == 46)
                        return true;
        }

        /* 34 byte requests seem to be met with 138-165 byte responses */
        if (data->payload_len[0] == 34 && (data->payload_len[1] <= 165 &&
                        data->payload_len[1] >= 138))
                return true;
        if (data->payload_len[1] == 34 && (data->payload_len[0] <= 165 &&
                        data->payload_len[0] >= 138))
                return true;

        /* 86 byte requests seem to be met with 100-225 byte responses */
        if (data->payload_len[0] == 86 && (data->payload_len[1] <= 225 &&
                        data->payload_len[1] >= 100))
                return true;
        if (data->payload_len[1] == 86 && (data->payload_len[0] <= 225 &&
                        data->payload_len[0] >= 100))
                return true;

        /* 193 matches 108 or 111 */
        if (data->payload_len[0] == 193 && (data->payload_len[1] == 108 ||
                        data->payload_len[1] == 111))
                return true;
        if (data->payload_len[1] == 193 && (data->payload_len[0] == 108 ||
                        data->payload_len[0] == 111))
                return true;

        /* The response to 73 bytes tends to vary in size */
        if (data->payload_len[0] == 73)
                return true;
        if (data->payload_len[1] == 73)
                return true;

        /* The response to 96 bytes tends to vary in size */
        if (data->payload_len[0] == 96)
                return true;
        if (data->payload_len[1] == 96)
                return true;

        /* The response to 28 bytes tends to vary in size, but is less than 
         * 200 */
        if (data->payload_len[0] == 28 && data->payload_len[1] < 200)
                return true;
        if (data->payload_len[1] == 28 && data->payload_len[0] < 200)
                return true;

        /* Same for 31 bytes */
        if (data->payload_len[0] == 31 && data->payload_len[1] < 200 &&
			data->payload_len[1] >= 40)
                return true;
        if (data->payload_len[1] == 31 && data->payload_len[0] < 200 &&
			data->payload_len[0] >= 40)
                return true;

        return false;

}

/* http://wiki.limewire.org/index.php?title=Out_of_Band_System */
static inline bool match_gnutella_oob(lpi_data_t *data) {

	/* DANGER: anonymised IP addresses! */
        if (!match_ip_address_both(data))
                return false;

        /* Payload size seems to be either 32 or 33 bytes */
        if (data->payload_len[0] == 32 || data->payload_len[1] == 32)
                return true;
        if (data->payload_len[0] == 33 || data->payload_len[1] == 33)
                return true;

        return false;

}


static inline bool match_gnutella_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_gnutella_oob(data))
		return true;
	
	if (match_gnutella_maint(data))
		return true;


	return false;
}

static lpi_module_t lpi_gnutella_udp = {
	LPI_PROTO_UDP_GNUTELLA,
	LPI_CATEGORY_P2P,
	"Gnutella_UDP",
	10,	/* Rules are pretty dodgy so make this low priority */
	match_gnutella_udp
};

void register_gnutella_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_gnutella_udp, mod_map);
}

