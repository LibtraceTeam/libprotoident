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
 * $Id: lpi_wechat_udp.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* Thanks to http://www.cse.cuhk.edu.hk/~pclee/www/pubs/iwqos15chatdissect.pdf
 * for helping confirm this rule */

static inline bool match_wechat_uplink_hb(uint32_t payload, uint32_t len) {

        /* Byte 3 appears to be a length indicator */
        if (MATCH(payload, 0xd1, 0x0a, 0x2e, 0x0a))
                return true;
        if (MATCH(payload, 0xd1, 0x0a, 0x2d, 0x0a))
                return true;
        if (MATCH(payload, 0xd1, 0x0a, 0x2c, 0x0a))
                return true;
        if (MATCH(payload, 0xd1, 0x0a, 0x1e, 0x0a))
                return true;
        if (MATCH(payload, 0xd1, 0x0a, 0x1d, 0x0a))
                return true;

        return false;

}

static inline bool match_wechat_downlink_hb(uint32_t payload, uint32_t len) {

        /* Byte 3 appears to be a length indicator */
        if (MATCHSTR(payload, "\xd1\x0a\x2b\x0a"))
                return true;
        if (MATCHSTR(payload, "\xd1\x0a\x2a\x0a"))
                return true;
        if (MATCHSTR(payload, "\xd1\x0a\x2d\x0a"))
                return true;

        return false;

}

static inline bool match_wechat_voip(uint32_t payload, uint32_t len) {

        if (!MATCH(payload, 0xa1, 0x08, ANY, ANY))
                return false;

        if (len == 92 || len == 75)
                return true;

        return false;
}

static inline bool match_wechat_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_wechat_uplink_hb(data->payload[0], data->payload_len[0])) {
                if (match_wechat_downlink_hb(data->payload[1],
                                data->payload_len[1]))
                        return true;
        }

        if (match_wechat_uplink_hb(data->payload[1], data->payload_len[1])) {
                if (match_wechat_downlink_hb(data->payload[0],
                                data->payload_len[0]))
                        return true;
        }
        
        if (match_wechat_voip(data->payload[0], data->payload_len[0])) {
                if (match_wechat_voip(data->payload[1],
                                data->payload_len[1]))
                        return true;
        }

        if (match_wechat_voip(data->payload[1], data->payload_len[1])) {
                if (match_wechat_voip(data->payload[0],
                                data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_wechat_udp = {
	LPI_PROTO_UDP_WECHAT,
	LPI_CATEGORY_CHAT,
	"WeChat_UDP",
	20,
	match_wechat_udp
};

void register_wechat_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_wechat_udp, mod_map);
}

