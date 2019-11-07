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

/* Based on both the QUIC spec: 
 *   https://docs.google.com/document/d/1WJvyZflAO2pq77yOLbp9NsGjC1CHetAXV8I0fQe-B_U/edit
 * and traffic observed in the wild.
 */

static inline bool match_quic_version(uint32_t payload) {

        /* Public flags for a Version Negotiation packet must be
         * 0x0d */
        if (MATCH(payload, 0x0d, ANY, ANY, ANY)) {
                return true;
        }

        /* 0x09 can also work in the case where there is no
         * diversification nonce in the header */
        if (MATCH(payload, 0x09, ANY, ANY, ANY)) {
                return true;
        }

        /* Apparently 0x0c and 0x0e can also work here? */
        if (MATCH(payload, 0x0c, ANY, ANY, ANY)) {
                return true;
        }

        if (MATCH(payload, 0x0e, ANY, ANY, ANY)) {
                return true;
        }


        return false;

}

static inline bool match_quic_response(uint32_t payload, uint32_t other) {

        uint32_t seq8 = (ntohl(payload) >> 16) & 0xff;

        /* Public flags are 0x00 for a packet with a single byte of
         * sequence number and no connection id */
        if (MATCH(payload, 0x00, ANY, ANY, ANY)) {
                /* This *is* UDP, so we might miss some of the first
                 * few datagrams... */
                if (seq8 >= 1 && seq8 <= 10)
                        return true;
        }


        /* Otherwise, connection IDs must match for both directions */
        if (MATCH(payload, 0x0c, ANY, ANY, ANY)) {
                if ((payload & 0xffffff00) == (other & 0xffffff00))
                        return true;
        }

        if (MATCH(payload, 0x0e, ANY, ANY, ANY)) {
                if ((payload & 0xffffff00) == (other & 0xffffff00))
                        return true;
        }

        /* This is the 4 byte connection ID case */
        if (MATCH(payload, 0x08, ANY, ANY, ANY)) {
                if ((payload & 0xffffff00) == (other & 0xffffff00))
                        return true;
        }

        /* This is the 4 byte diversification nonce case, with no other
         * flags set. */
        if (MATCH(payload, 0x04, ANY, ANY, ANY)) {
                return true;
        }


        return false;

}

static inline bool match_quic_port(lpi_data_t *data) {
        if (data->server_port == 443)
                return true;
        if (data->client_port == 443)
                return true;

        if (data->server_port == 80)
                return true;
        if (data->client_port == 80)
                return true;

        return false;
}

/* Match old Google QUIC versions */
static inline bool match_old_gquic(lpi_data_t *data) {

        if (match_quic_version(data->payload[0])) {
                if (match_quic_response(data->payload[1], data->payload[0]))
                        return true;
        }

        if (match_quic_version(data->payload[1])) {
                if (match_quic_response(data->payload[0], data->payload[1]))
                        return true;
        }


        /* Matches against an in-progress QUIC flow 
         * XXX not overly robust, may produce false positives... */
        if (MATCH(data->payload[0], 0x10, ANY, ANY, ANY)) {
                if (MATCH(data->payload[1], 0x0c, ANY, ANY, ANY))
                        return true;
                if (MATCH(data->payload[1], 0x1c, ANY, ANY, ANY))
                        return true;
        }

        if (MATCH(data->payload[0], 0x00, ANY, ANY, ANY)) {
                if (MATCH(data->payload[1], 0x0c, ANY, ANY, ANY))
                        return true;
                if (MATCH(data->payload[1], 0x1c, ANY, ANY, ANY))
                        return true;
        }

        if (MATCH(data->payload[1], 0x10, ANY, ANY, ANY)) {
                if (MATCH(data->payload[0], 0x0c, ANY, ANY, ANY))
                        return true;
                if (MATCH(data->payload[0], 0x1c, ANY, ANY, ANY))
                        return true;
        }

        if (MATCH(data->payload[1], 0x00, ANY, ANY, ANY)) {
                if (MATCH(data->payload[0], 0x0c, ANY, ANY, ANY))
                        return true;
                if (MATCH(data->payload[0], 0x1c, ANY, ANY, ANY))
                        return true;
        }

        return false;
}

static inline bool match_req_q044(uint32_t payload, uint32_t len) {

        if (MATCHSTR(payload, "\xffQ04") && len == 1350) {
                return true;
        }

        /* IPv6 */
        if (MATCHSTR(payload, "\xffQ04") && len == 1330) {
                return true;
        }
        if (MATCH(payload, 0xc3, 'Q', '0', '4') &&
                        (len == 1350 || len == 1330)) {
                return true;
        }
        return false;
}

static inline bool match_reply_q044(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0xff, 'Q', '0', '4')) {
                return true;
        }
        if (MATCH(payload, 0xfd, 'Q', '0', '4')) {
                return true;
        }
        if (MATCH(payload, 0xfc, 'Q', '0', '4')) {
                return true;
        }
        if (MATCH(payload, 0xc3, 'Q', '0', '4')) {
                return true;
        }
        if (MATCH(payload, 0xd3, 'Q', '0', '4')) {
                return true;
        }
        if (MATCH(payload, 0xe3, 'Q', '0', '4')) {
                return true;
        }
        return false;
}

/* IETF QUIC version 44, starting to be deployed by Google */
static inline bool match_quic_044(lpi_data_t *data) {

        if (match_req_q044(data->payload[0], data->payload_len[0])) {
                if (match_reply_q044(data->payload[1], data->payload_len[1])) {
                        return true;
                }
        }

        if (match_req_q044(data->payload[1], data->payload_len[1])) {
                if (match_reply_q044(data->payload[0], data->payload_len[0])) {
                        return true;
                }
        }

        return false;
}

static inline bool match_reply_fbquic(uint32_t payload, uint32_t len) {
        if (len >= 45 && len <= 50) {
                if ((ntohl(payload) & 0xf0000000) != 0xc0000000) {
                        return false;
                }
                if (MATCH(payload, ANY, 0xfa, 0xce, 0xb0)) {
                        return true;
                }
        }
        return false;
}

static inline bool match_req_fbquic(uint32_t payload, uint32_t len) {
        if (len == 1235) {
                if ((ntohl(payload) & 0xf0000000) != 0xc0000000) {
                        return false;
                }
                if (MATCH(payload, ANY, 0xfa, 0xce, 0xb0)) {
                        return true;
                }
        }
        return false;
}

static inline bool match_fb_quic(lpi_data_t *data) {
        if (match_req_fbquic(data->payload[0], data->payload_len[0])) {
                if (match_reply_fbquic(data->payload[1], data->payload_len[1]))
                        return true;
        }
        if (match_req_fbquic(data->payload[1], data->payload_len[1])) {
                if (match_reply_fbquic(data->payload[0], data->payload_len[0]))
                        return true;
        }
        return false;
}

static inline bool match_quic(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (!match_quic_port(data))
                return false;

        /* Spec says that packets must not be larger than 1350 bytes */
        if (data->payload_len[0] > 1350 || data->payload_len[1] > 1350)
                return false;

        if (match_quic_044(data)) {
                return true;
        }

        if (match_fb_quic(data)) {
                return true;
        }

        if (match_old_gquic(data)) {
                return true;
        }

	return false;
}

static lpi_module_t lpi_quic = {
	LPI_PROTO_UDP_QUIC,
	LPI_CATEGORY_WEB,
	"QUIC",
	9,
	match_quic
};

void register_quic(LPIModuleMap *mod_map) {
	register_protocol(&lpi_quic, mod_map);
}

