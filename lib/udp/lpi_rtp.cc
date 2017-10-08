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

static inline bool match_rtp_payload(uint32_t payload, uint32_t len, 
		uint32_t other_len) {

	/* This rule seems very weak -- maybe need to capture some known
         * RTP traffic to try and strengthen it?
         */

        /* Be stricter about packet length when looking at one-way flows */
	if (other_len == 0) {
		if (len != 32 && len != 92 && len != 172 && 
                                len != 31 && len != 24)
			return false;
	}

	if (MATCH(payload, 0x80, ANY, ANY, ANY))
		return true;
	if (MATCH(payload, 0x90, ANY, ANY, ANY))
		return true;

	return false;

}

static inline bool match_rtp_806d(uint32_t payload, uint32_t len) {

        /* Common pattern we see on our local videoconf server */
        if (len == 24 && MATCH(payload, 0x80, 0x6d, 0x00, 0x00))
                return true;
        return false;

}

static inline bool match_stun_response(uint32_t payload, uint32_t len) {

	/* Many VOIP phones use STUN for NAT traversal, so the response to
	 * outgoing RTP is often a STUN packet */

	if (len == 28 && MATCH(payload, 0x00, 0x01, 0x00, 0x08))
		return true;
        if (len == 12 && MATCH(payload, 0x00, 0x11, 0x00, 0x00))
                return true;

        /* Facebook-specific STUN? Message type 0x003 is not defined in
         * any official STUN documentation */
        if (len == 126 && MATCH(payload, 0x00, 0x03, 0x00, 0x6a))
                return true;

	return false;

}

static inline bool match_rtp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Watch out for one-way DNS... */
	if (data->client_port == 53 || data->client_port == 53) {
		if (data->payload_len[0] == 0 || data->payload_len[1] == 0)
			return false;
	}

        if (match_rtp_806d(data->payload[0], data->payload_len[0])) {
                if (match_rtp_payload(data->payload[1], data->payload_len[1],
                                data->payload_len[0]))
                        return true;
        }

        if (match_rtp_806d(data->payload[1], data->payload_len[1])) {
                if (match_rtp_payload(data->payload[0], data->payload_len[0],
                                data->payload_len[1]))
                        return true;
        }


	if (match_rtp_payload(data->payload[0], data->payload_len[0], 
			data->payload_len[1])) {
		if (match_stun_response(data->payload[1], data->payload_len[1]))
			return true;
		if (match_rtp_payload(data->payload[1], data->payload_len[1], 
				data->payload_len[0])) {
			uint32_t a = ntohl(data->payload[0]) & 0xffff0000;
			uint32_t b = ntohl(data->payload[1]) & 0xffff0000;

			if (a == b)
				return true;
			return false;
		}
		if (data->payload_len[1] == 0)
			return true;
	}

	if (match_rtp_payload(data->payload[1], data->payload_len[1], 
			data->payload_len[0])) {
		if (match_stun_response(data->payload[0], data->payload_len[0]))
			return true;
		if (data->payload_len[0] == 0)
			return true;
	}
	return false;
}

static lpi_module_t lpi_rtp = {
	LPI_PROTO_UDP_RTP,
	LPI_CATEGORY_VOIP,
	"RTP",
	33,
	match_rtp
};

void register_rtp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_rtp, mod_map);
}

