/*
 *
 * Copyright (c) 2011-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libprotoident.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_skype_rule1(lpi_data_t *data) {

        /* This is one method for matching skype traffic - turns out there
         * are other forms as well... */

        /* The third byte is always 0x02 in Skype UDP traffic - if we have
         * payload in both directions we can probably match on that alone */

	uint32_t payload0 = ntohl(data->payload[0]);
	uint32_t payload1 = ntohl(data->payload[1]);


        if (data->payload_len[0] > 0 && data->payload_len[1] > 0) {
                if ((payload0 & 0x0000ff00) != 0x00000200)
                        return false;
                if ((payload1 & 0x0000ff00) != 0x00000200)
                        return false;
                return true;
        }

        /* Probes with no responses are trickier - likelihood of a random
         * packet having 0x02 as the third byte is not small, so we'll try
         * and filter on packet size too */

        if (data->payload_len[0] >= 18 && data->payload_len[0] <= 137 ) {
                if ((payload0 & 0x0000ff00) == 0x00000200)
                        return true;
        }
        if (data->payload_len[1] >= 18 && data->payload_len[1] <= 137 ) {
                if ((payload1 & 0x0000ff00) == 0x00000200)
                        return true;
        }

        return false;
}


static inline bool match_skype_U1(uint32_t payload, uint32_t len) {

        if (len < 18)
                return false;
        if ((ntohl(payload) & 0x0000ff00) == 0x00000200)
                return true;

        return false;

}

static inline bool match_skype_U2(uint32_t payload, uint32_t len) {

        if (len != 11)
                return false;
        if ((ntohl(payload) & 0x00000f00) == 0x00000500)
                return true;
        if ((ntohl(payload) & 0x00000f00) == 0x00000700)
                return true;
        return false;
}


static inline bool match_skype_rule2(lpi_data_t *data) {

        /* What we're looking for here is a initiating message (called U1)
         * matched with a response (called U2).
         *
         * The first two bytes of U1 and U2 must match.
         *
         * The third byte of U1 is always 0x02 (as with rule 1)
         * 
         * The lower four bits of the third byte of U2 is always either 0x05
         * or 0x07
         *
         * The length of U2 is always 11 bytes.
         *
         * The length of U1 is always between 18 and 31 bytes.
         */

        if ((ntohl(data->payload[0]) & 0xffff0000) != 
			(ntohl(data->payload[1]) & 0xffff0000))
                return false;

        if (match_skype_U1(data->payload[0], data->payload_len[0])) {
                if (match_skype_U2(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_skype_U1(data->payload[1], data->payload_len[1])) {
                if (match_skype_U2(data->payload[0], data->payload_len[0]))
                        return true;
        }

        return false;
}


static inline bool match_meeting_stun_request(uint32_t payload, uint32_t len) {

        if ((ntohl(payload) & 0xffff) != len - 4)
                return false;

        /* Checking for 0xff + ANY bytes is hard :( */
        if ((ntohl(payload) & 0xff000000) != 0xff000000)
                return false;

        if (MATCH(payload, ANY, 0x10, ANY, ANY))
                return true;

        return false;

}

static inline bool match_meeting_stun_reply(uint32_t payload, uint32_t len) {

        if ((ntohl(payload) & 0xffff) != len - 20)
                return false;

        if (MATCH(payload, 0x00, 0x01, ANY, ANY))
                return true;
        if (MATCH(payload, 0x01, 0x01, ANY, ANY))
                return true;

        return false;

}

static inline bool match_skype_meeting_broadcast(lpi_data_t *data) {
        /* This protocol is a LOT like STUN, but isn't really STUN. */

        /* TODO get hold of skype for business and double check this */

        if (match_meeting_stun_request(data->payload[0], data->payload_len[0]))
        {
                if (match_meeting_stun_reply(data->payload[1],
                                        data->payload_len[1])) {
                        return true;
                }
        }

        if (match_meeting_stun_request(data->payload[1], data->payload_len[1]))
        {
                if (match_meeting_stun_reply(data->payload[0],
                                        data->payload_len[0])) {
                        return true;
                }
        }

        return false;
}

static inline bool match_skype(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_skype_rule1(data))
                return true;
        if (match_skype_rule2(data))
                return true;


        if (match_skype_meeting_broadcast(data))
                return true;

	return false;
}

static lpi_module_t lpi_skype = {
	LPI_PROTO_UDP_SKYPE,
	LPI_CATEGORY_VOIP,
	"Skype",
	105,	/* The Skype rules aren't strong, so have a low priority */
	match_skype
};

void register_skype(LPIModuleMap *mod_map) {
	register_protocol(&lpi_skype, mod_map);
}

