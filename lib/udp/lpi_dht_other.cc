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

/* http://xbtt.sourceforge.net/udp_tracker_protocol.html */
static inline bool match_xbt_tracker(lpi_data_t *data) {

        if (data->payload_len[0] != 0 && data->payload_len[0] != 16)
                return false;
        if (data->payload_len[1] != 0 && data->payload_len[1] != 16)
                return false;

        if (!match_chars_either(data, 0x00, 0x00, 0x04, 0x17))
                return false;

        if (data->payload_len[0] == 0 || data->payload_len[1] == 0)
                return true;

        if (data->payload_len[0] == 16 && data->payload_len[1] == 16 &&
                        match_chars_either(data, 0x00, 0x00, 0x00, 0x00))
                return true;

        return false;

}


static inline bool match_unknown_btudp(lpi_data_t *data) {

        /* I have not been able to figure out exactly what this stuff
         * is, but I'm pretty confident it is somehow related to a
         * BitTorrent implementation or two */

        /* The recipient does not reply */
        if (data->payload_len[0] > 0 && data->payload_len[1] > 0)
                return false;

        if (!(match_str_both(data, "\x00\x00\x00\x00", "\x00\x00\x00\x00")))
                return false;

        if (data->payload_len[0] == 14 || data->payload_len[0] == 18)
                return true;
        if (data->payload_len[1] == 14 || data->payload_len[1] == 18)
                return true;

        return false;

}

static inline bool match_vuze_dht_request(uint32_t payload, uint32_t len,
                bool check_msb) {


        /* Some implementations don't choose an appropriate MSB or get the
         * byte ordering wrong, so we only force an MSB check when we're
         * examining requests that get no response.
         */

        if (len < 4)
                return false;

        if (check_msb) {

                if ((ntohl(payload) & 0x80000000) != 0x80000000)
                        return false;

        } else {
                /* Automatically return true if the MSB is set, regardless of
                 * request size */

                if ((ntohl(payload) & 0x80000000) == 0x80000000)
                        return true;
        }


        if (len == 42 || len == 51) {
                return true;
        }

        if (len == 63 || len == 65 || len == 71)
                return true;

        return false;

}

static inline bool match_vuze_dht_reply(uint32_t data, uint32_t len) {

        /* Each reply action is an odd number */

        if (MATCH(data, 0x00, 0x00, 0x04, 0x01))
                return true;
        if (MATCH(data, 0x00, 0x00, 0x04, 0x03))
                return true;
        if (MATCH(data, 0x00, 0x00, 0x04, 0x05))
                return true;
        if (MATCH(data, 0x00, 0x00, 0x04, 0x07))
                return true;

        /* Except for this one, which is an error message */
        if (MATCH(data, 0x00, 0x00, 0x04, 0x08))
                return true;

        return false;


}

static inline bool match_vuze_dht_alt(lpi_data_t *data) {

        /* Flows matching this rule *appear* to be doing something related
         * to the Vuze DHT system, but this behaviour is undocumented.
         *
         * I have observed flows that match the conventional Vuze DHT rule
         * involving the same IP/port as flows that match this rule, so
         * that does suggest it is related to Vuze somehow. */

        if (data->payload_len[0] != 0 &&
                        (ntohl(data->payload[0]) & 0x80000000) != 0x80000000)
                return false;
        if (data->payload_len[1] != 0 &&
                        (ntohl(data->payload[1]) & 0x80000000) != 0x80000000)
                return false;

        if (data->payload_len[0] == 90 && data->payload_len[1] == 79)
                return true;
        if (data->payload_len[1] == 90 && data->payload_len[0] == 79)
                return true;
        if (data->payload_len[0] == 90 && data->payload_len[1] == 0)
                return true;
        if (data->payload_len[1] == 90 && data->payload_len[0] == 0)
                return true;

        return false;
}


static inline bool match_vuze_dht(lpi_data_t *data) {

        /* OK, gotta rework this one as this protocol is a bit messed up in 
         * the implementation.
         *
         * Normally, we have a request which contains a random number in
         * the first four bytes. However, the MSB of that number must be
         * set to one.
         *
         * The reply begins with a four byte action which is easy to identify.
         *
         * However, we also get replies in both directions (which is a bit
         * odd). I'm also seeing requests where the MSB is not set, which is
         * a definite violation.
         *
         * However, I think we want to count these - they are clearly attempts
         * to use this protocol so classing them as unknown doesn't seem
         * right.
         */

        if (match_vuze_dht_reply(data->payload[0], data->payload_len[0])) {

                if (data->payload_len[1] == 0)
                        return true;

                if (match_vuze_dht_request(data->payload[1],
                                data->payload_len[1], false))
                        return true;

                /* Check for replies in both directions */
                if (match_vuze_dht_reply(data->payload[1],
                                data->payload_len[1]))
                        return true;

        }
        if (match_vuze_dht_reply(data->payload[1], data->payload_len[1])) {

                if (data->payload_len[0] == 0)
                        return true;

                if (match_vuze_dht_request(data->payload[0],
                                data->payload_len[0], false))
                        return true;

                /* Check for replies in both directions */
                if (match_vuze_dht_reply(data->payload[0],
                                data->payload_len[0]))
                        return true;

        }

        /* Check for unanswered requests - these are much harder to match,
         * because they are simply a random conn id. We can only hope to match
         * on common packet sizes and the MSB being set 
         *
         * XXX This could lead to a few false positives, so be careful */

        if (data->payload[0] == 0) {
                if (match_vuze_dht_request(data->payload[1],
                                data->payload_len[1], true))
                        return true;
        }

        if (data->payload[1] == 0) {
                if (match_vuze_dht_request(data->payload[0],
                                data->payload_len[0], true))
                        return true;
        }

	/* Apparently, we can also see requests both ways, which is a bit
	 * less than ideal....
	 */
	if (match_vuze_dht_request(data->payload[0], data->payload_len[0], true) && match_vuze_dht_request(data->payload[1], data->payload_len[1], true))
		return true;
	

        if (match_vuze_dht_alt(data))
                return true;

        return false;



}

static inline bool match_unknown_dht(lpi_data_t *data) {

        /* I don't know exactly what BT clients do this, but there are often
         * DHT queries and responses present in flows that match this rule,
         * so we're going to go with some form of Bittorrent */

        if (data->payload[0] == 0 || data->payload[1] == 0)
                return false;

        /* Both initial packets are 33 bytes and have the exact same 
         * payload */
        if (data->payload_len[0] != 33 || data->payload_len[1] != 33)
                return false;

        if (data->payload[0] != data->payload[1])
                return false;

        return true;

}


static inline bool match_dht_other(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_unknown_btudp(data))
		return true;	
	if (match_vuze_dht(data))
		return true;
	if (match_xbt_tracker(data))
		return true;
	if (match_unknown_dht(data))
		return true;

	return false;
}

static lpi_module_t lpi_dht_other = {
	LPI_PROTO_UDP_BTDHT,
	LPI_CATEGORY_P2P,
	"BitTorrent_UDP",
	12,	/* Need to be lower priority than DNS, at least in cases 
		 * where traffic is one-way only */
	match_dht_other
};

void register_dht_other(LPIModuleMap *mod_map) {
	register_protocol(&lpi_dht_other, mod_map);
}

