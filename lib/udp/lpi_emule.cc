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

static inline bool match_emule_kad(uint32_t payload, uint32_t len) {

        /* Many of these can be tracked back to
         * http://easymule.googlecode.com/svn/trunk/src/WorkLayer/opcodes.h
         *
         * XXX Some of these are request/response pairs that we may need to
         * match together if we start getting false positives 
         */


        /* Bootstrap version 2 request and response */
        if (MATCH(payload, 0xe4, 0x00, ANY, ANY) && len == 27)
                return true;
        if (MATCH(payload, 0xe4, 0x08, ANY, ANY) && len == 529)
                return true;

        /* Bootstrap version 2 request and response */
        if (MATCH(payload, 0xe4, 0x01, 0x00, 0x00) && (
                        len == 2 || len == 18))
                return true;
        if (MATCH(payload, 0xe4, 0x09, ANY, ANY) && len == 523)
                return true;


        if (MATCH(payload, 0xe4, 0x21, ANY, ANY) && len == 35)
                return true;
        if (MATCH(payload, 0xe4, 0x4b, ANY, ANY) && len == 19)
                return true;
        if (MATCH(payload, 0xe4, 0x11, ANY, ANY)) {
                return true;
        }

        if (MATCH(payload, 0xe4, 0x19, ANY, ANY)) {
                if (len == 22 || len == 38 || len == 28)
                        return true;
        }

        if (MATCH(payload, 0xe4, 0x20, ANY, ANY) && len == 35)
                return true;

        if (MATCH(payload, 0xe4, 0x18, ANY, ANY) && len == 27)
                return true;

        if (MATCH(payload, 0xe4, 0x10, ANY, ANY) && len == 27)
                return true;

        if (MATCH(payload, 0xe4, 0x58, ANY, ANY) && len == 6)
                return true;

        if (MATCH(payload, 0xe4, 0x50, ANY, ANY) && len == 4)
                return true;

        if (MATCH(payload, 0xe4, 0x52, ANY, ANY) && len == 36)
                return true;

        if (MATCH(payload, 0xe4, 0x40, ANY, ANY) && len == 48)
                return true;

        if (MATCH(payload, 0xe4, 0x43, ANY, ANY) && len == 225)
                return true;

        if (MATCH(payload, 0xe4, 0x48, ANY, ANY) && len == 19)
                return true;

        if (MATCH(payload, 0xe4, 0x29, ANY, ANY)) {
                if (len == 119 || len == 69 || len == 294)
                        return true;
        }

        if (MATCH(payload, 0xe4, 0x28, ANY, ANY)) {
                if (len == 119 || len == 69 || len == 294)
                        return true;
                if (len == 44)
                        return true;
                if (len == 269)
                        return true;
        }

	return false;
}


static bool is_emule_udp(uint32_t payload, uint32_t len) {

        /* Mainly looking at Kad stuff here - Kad packets start with 0xe4
         * for uncompressed and 0xe5 for compressed data */


        if (MATCH(payload, 0xe5, 0x43, ANY, ANY))
                return true;
        if (MATCH(payload, 0xe5, 0x08, 0x78, 0xda))
                return true;
        if (MATCH(payload, 0xe5, 0x28, 0x78, 0xda))
                return true;

        /* emule extensions */
        if (MATCH(payload, 0xc5, 0x90, ANY, ANY)) {
                return true;
        }
        if (MATCH(payload, 0xc5, 0x91, ANY, ANY)) {
                return true;
        }
        if (MATCH(payload, 0xc5, 0x92, ANY, ANY) && (len == 2))
                return true;
        if (MATCH(payload, 0xc5, 0x93, ANY, ANY) && (len == 2))
                return true;
        if (MATCH(payload, 0xc5, 0x94, ANY, ANY)) {
                if (len >= 38 && len <= 70)
                        return true;
        }

        /* 0xe3 covers conventional emule messages */
        if (MATCH(payload, 0xe3, 0x9a, ANY, ANY))
                return true;
        if (MATCH(payload, 0xe3, 0x9b, ANY, ANY))
                return true;
        if (MATCH(payload, 0xe3, 0x96, ANY, ANY) && len == 6)
                return true;

        if (MATCH(payload, 0xe3, 0x97, ANY, ANY)) {
                if (len <= 34 && ((len - 2) % 4 == 0))
                        return true;
        }
        if (MATCH(payload, 0xe3, 0x92, ANY, ANY))
                return true;
        if (MATCH(payload, 0xe3, 0x94, ANY, ANY))
                return true;
        if (MATCH(payload, 0xe3, 0x98, ANY, ANY))
                return true;
        if (MATCH(payload, 0xe3, 0x99, ANY, ANY))
                return true;
        if (MATCH(payload, 0xe3, 0xa2, ANY, ANY) && len == 6)
                return true;
        if (MATCH(payload, 0xe3, 0xa3, ANY, ANY))
                return true;




        if (match_emule_kad(payload, len))
                return true;


        return false;

}

static inline bool match_emule_verycd(uint32_t payload, uint32_t len) {

        /* Later packets in the flow are clearly referencing eMule builds
         * and software, in particular VeryCD and xl build61 */
        if (len != 31)
                return false;
        if (!MATCH(payload, 0x3b, 0x00, 0x00, 0x00))
                return false;
        return true;

}


static inline bool match_emule_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_emule(data))
		return true;

        if (data->payload_len[0] == 0 &&
                        is_emule_udp(data->payload[1], data->payload_len[1])) {
                return true;
        }

        if (data->payload_len[1] == 0 &&
                        is_emule_udp(data->payload[0], data->payload_len[0])) {
                return true;
        }

        if (is_emule_udp(data->payload[0], data->payload_len[0]) &&
                        is_emule_udp(data->payload[1], data->payload_len[1]))
                return true;


        /* Having doubts about the correctness of this rule, so disabling
         * for now. */
        /*
        if (match_emule_verycd(data->payload[0], data->payload_len[0])) {
                if (data->payload_len[1] != 0)
                        return true;
        }

        if (match_emule_verycd(data->payload[1], data->payload_len[1])) {
                if (data->payload_len[0] != 0)
                        return true;
        }
        */

	return false;
}

static lpi_module_t lpi_emule_udp = {
	LPI_PROTO_UDP_EMULE,
	LPI_CATEGORY_P2P,
	"eMule_UDP",
	11,
	match_emule_udp
};

void register_emule_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_emule_udp, mod_map);
}

