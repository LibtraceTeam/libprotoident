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

/* Protocol used by Baidu Yun for sharing files between friends. Not
 * 100% confirmed, but I've managed to observe other confirmed Baidu Yun
 * traffic for the same host / port prior to the suspected peer starting
 * flows matching this pattern.
 *
 * For some reason I was unable to make P2P transfers work when using Baidu
 * Yun myself (possibly because I was behind NAT?), which is why I haven't
 * been able to confirm.
 */

static inline bool match_byun_p2p(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;

        if (len == 64 || len == 32) {
                if (MATCH(payload, 0x01, ANY, ANY, ANY))
                        return true;
        }
        return false;

}

static inline bool match_baiduyun_p2p(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->server_port != 7273 && data->client_port != 7273 &&
                        data->server_port != 7274 &&
                        data->client_port != 7274)
                return false;


        if (match_byun_p2p(data->payload[0], data->payload_len[0])) {
                if (match_byun_p2p(data->payload[1], data->payload_len[1]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_baiduyun_p2p = {
	LPI_PROTO_UDP_BAIDU_YUN_P2P,
	LPI_CATEGORY_P2P,
	"BaiduYunP2P",
	100,
	match_baiduyun_p2p
};

void register_baiduyun_p2p(LPIModuleMap *mod_map) {
	register_protocol(&lpi_baiduyun_p2p, mod_map);
}

