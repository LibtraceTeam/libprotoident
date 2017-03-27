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

static inline bool match_shuijing_44(uint32_t payload, uint32_t len) {
        if (MATCH(payload, 0x44, 0x00, 0x00, 0x00))
                return true;
        if (MATCH(payload, 0x42, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_shuijing_3e(uint32_t payload, uint32_t len) {
        if (MATCH(payload, 0x3e, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_shuijing_41(uint32_t payload, uint32_t len) {
        if (MATCH(payload, 0x41, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_shuijing_46(uint32_t payload, uint32_t len) {
        if (MATCH(payload, 0x46, 0x00, 0x00, 0x00))
                return true;
        return false;
}

static inline bool match_xunlei_3e(uint32_t payload, uint32_t len) {
        if (len == 132 && MATCH(payload, 0x3e, 0x00, 0x00, 0x00))
                return true;
        return false;

}

static inline bool match_xunlei_36(uint32_t payload, uint32_t len) {
        if (len == 51 && MATCH(payload, 0x36, 0x00, 0x00, 0x00))
                return true;
        return false;

}

static inline bool match_xunlei(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/*
        if (match_str_both(data, "\x3c\x00\x00\x00", "\x3c\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x3d\x00\x00\x00", "\x39\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x3d\x00\x00\x00", "\x3a\x00\x00\x00"))
                return true;
        */

        if (match_str_both(data, "\x29\x00\x00\x00", "\x29\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x36\x00\x00\x00", "\x33\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x36\x00\x00\x00", "\x36\x00\x00\x00"))
                return true;
        if (match_str_either(data, "\x33\x00\x00\x00")) {
                if (data->payload_len[0] == 0 && data->payload_len[1] == 87)
                        return true;
                if (data->payload_len[1] == 0 && data->payload_len[0] == 87)
                        return true;
        }

        if (match_str_either(data, "\x36\x00\x00\x00")) {
                if (data->payload_len[0] == 0 && data->payload_len[1] == 71)
                        return true;
                if (data->payload_len[1] == 0 && data->payload_len[0] == 71)
                        return true;
        }

        if (match_str_either(data, "\x29\x00\x00\x00")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }


        /* Pretty sure this is "Thunder Crystal" (a.k.a. Xunlei Shuijing),
         * a P2P approach to doing CDN. Uses TCP port 4593, usually.
         * Ref: http://dl.acm.org/citation.cfm?id=2736085
         *
         * XXX Should this be a separate protocol?
         */

        if (match_shuijing_44(data->payload[0], data->payload_len[0])) {
                if (match_shuijing_3e(data->payload[1], data->payload_len[1]))
                        return true;
                if (match_shuijing_46(data->payload[1], data->payload_len[1]))
                        return true;
                if (match_shuijing_44(data->payload[1], data->payload_len[1]))
                        return true;
                if (match_shuijing_41(data->payload[1], data->payload_len[1]))
                        return true;
        }
        if (match_shuijing_44(data->payload[1], data->payload_len[1])) {
                if (match_shuijing_3e(data->payload[0], data->payload_len[0]))
                        return true;
                if (match_shuijing_46(data->payload[0], data->payload_len[0]))
                        return true;
                if (match_shuijing_44(data->payload[0], data->payload_len[0]))
                        return true;
                if (match_shuijing_41(data->payload[0], data->payload_len[0]))
                        return true;
        }

        
        /* Almost certainly Xunlei-related, appears on port 8080 to hosts
         * that are in subnets used by Xunlei. Many IP ranges appear in
         * http://ipfilter-emule.googlecode.com/svn/trunk/ipfilter-xl/.htaccess?id=htxl
         * 
         * Update: the above URL no longer exists, but thankfully archive.org
         * has saved a copy:
         *   http://web.archive.org/web/20160410231755/http://ipfilter-emule.googlecode.com/svn/trunk/ipfilter-xl/.htaccess
         */

        if (match_xunlei_3e(data->payload[0], data->payload_len[0])) {
                if (match_xunlei_36(data->payload[1], data->payload_len[1])) {
                        return true;
                }
        }

        if (match_xunlei_3e(data->payload[1], data->payload_len[1])) {
                if (match_xunlei_36(data->payload[0], data->payload_len[0])) {
                        return true;
                }
        }


	return false;
}

static lpi_module_t lpi_xunlei = {
	LPI_PROTO_XUNLEI,
	LPI_CATEGORY_P2P,
	"Xunlei",
	3,
	match_xunlei
};

void register_xunlei(LPIModuleMap *mod_map) {
	register_protocol(&lpi_xunlei, mod_map);
}

