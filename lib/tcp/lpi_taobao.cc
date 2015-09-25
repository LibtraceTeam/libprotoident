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

/* Not entirely sure what this protocol is. Observed flows involve Taobao
 * CDN hosts and TCP port 80, but it is clearly not HTTP. Users doing this
 * protocol also speak conventional HTTP and HTTPS to the same Taobao host
 * at the same time, so it isn't a substitute for HTTP. Possibly a streaming
 * media protocol?
 *
 * For now I'm just going to use the generic name 'Taobao' and hope that
 * we can figure this out some time in the future.
 */

static inline bool match_taobao_req(uint32_t payload, uint32_t len) {
        /* Byte 4 is a length field, == len - 4 */

        if (len == 202 && MATCH(payload, 0xf5, 0x00, 0x00, 0xc6))
                return true;
        return false;

}

static inline bool match_taobao_req2(uint32_t payload, uint32_t len) {
        /* Byte 4 is a length field, == len - 4 */

        if (len == 74 && MATCH(payload, 0xf1, 0x00, 0x00, 0x46))
                return true;
        return false;

}

static inline bool match_taobao_resp(uint32_t payload, uint32_t len) {
        /* Byte 4 is a length field, == len - 4 */

        if (len == 58 && MATCH(payload, 0xf3, 0x00, 0x00, 0x36))
                return true;
        return false;

}

static inline bool match_taobao_resp2(uint32_t payload, uint32_t len) {
        /* Byte 4 is a length field, == len - 4 */

        if (len == 174 && MATCH(payload, 0xf3, 0x00, 0x00, 0xaa))
                return true;
        return false;

}

static inline bool match_taobao(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_taobao_req(data->payload[0], data->payload_len[0])) {
                if (match_taobao_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_taobao_req(data->payload[1], data->payload_len[1])) {
                if (match_taobao_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_taobao = {
	LPI_PROTO_TAOBAO,
	LPI_CATEGORY_CDN,
	"Taobao",
	20,
	match_taobao
};

void register_taobao(LPIModuleMap *mod_map) {
	register_protocol(&lpi_taobao, mod_map);
}

