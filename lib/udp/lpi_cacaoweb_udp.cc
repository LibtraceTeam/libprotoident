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

static inline bool match_cacao_smalla(uint32_t payload, uint32_t len) {

        if (len > 15)
                return false;

        if ((ntohl(payload) & 0xa0000000) == 0xa0000000)
                return true;
        return false;
}

static inline bool match_cacao_other(uint32_t payload, uint32_t opp) {

        uint32_t firsta = ntohl(payload) >> 24;
        uint32_t lastb = ntohl(opp) & 0xff;

        if (firsta == lastb && firsta != 0)
                return true;
        return false;

}

static inline bool match_cacao_c0_12(uint32_t payload, uint32_t len) {
        if (len == 12 && MATCH(payload, 0xc0, ANY, ANY, ANY))
                return true;
        return false;
}

static inline bool match_cacao_c0_14(uint32_t payload, uint32_t len) {
        if (len == 14 && MATCH(payload, 0xc0, ANY, ANY, ANY))
                return true;
        return false;
}

static inline bool match_cacaoweb_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_cacao_smalla(data->payload[0], data->payload_len[0])) {
                if (match_cacao_other(data->payload[1], data->payload[0])) {
                        return true;
                }
        }

        if (match_cacao_smalla(data->payload[1], data->payload_len[1])) {
                if (match_cacao_other(data->payload[0], data->payload[1])) {
                        return true;
                }
        }

        if (match_cacao_c0_12(data->payload[0], data->payload_len[0])) {
                if (match_cacao_c0_14(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_cacao_c0_12(data->payload[1], data->payload_len[1])) {
                if (match_cacao_c0_14(data->payload[0], data->payload_len[0]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_cacaoweb_udp = {
	LPI_PROTO_UDP_CACAOWEB,
	LPI_CATEGORY_P2P,
	"CacaowebUDP",
	231,
	match_cacaoweb_udp
};

void register_cacaoweb_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_cacaoweb_udp, mod_map);
}

