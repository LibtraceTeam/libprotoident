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

static inline bool obs_pplive_req(uint32_t len) {
	/* There's always a 94 byte packet involved */
	if (len == 94)
		return true;
	return false;
}

static inline bool obs_pplive_resp(uint32_t len) {
	if (len == 0)
		return true;
	if (len == 94)
		return true;
	if (len == 49)
		return true;
	return false;
}


static inline bool match_obscure_pplive(lpi_data_t *data) {

	/* This is pretty tough stuff to match - the 4 bytes of payload
	 * is random, but the packet sizes seem consistent. It also seems to
	 * only occur on certain ports.
	 *
	 * DPI tools suggest this traffic is pplive, so we'll go with that
	 * in the absence of any other documentation :/
	 */

	/* Port 5041 and 8303 are the ports that this traffic is
	 * typically seen on  */
	if (data->server_port != 5041 && data->server_port != 8303 &&
			data->client_port != 5041 && data->client_port != 8303)
		return false;

	if (obs_pplive_req(data->payload_len[0]) && 
			obs_pplive_resp(data->payload_len[1]))
		return true;
	if (obs_pplive_req(data->payload_len[1]) && 
			obs_pplive_resp(data->payload_len[0]))
		return true;

	return false;

}

static inline bool match_pplive(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_str_both(data, "\xe9\x03\x41\x01", "\xe9\x03\x42\x01"))
                return true;
        if (match_str_both(data, "\xe9\x03\x41\x01", "\xe9\x03\x41\x01"))
                return true;
        if (match_str_either(data, "\xe9\x03\x41\x01")) {
                if (data->payload_len[0] == 0 && data->payload_len[1] == 57)
                        return true;
                if (data->payload_len[1] == 0 && data->payload_len[0] == 57)
                        return true;
        }
        /* According to a Chinese paper (Xiaona et al), this is a pattern
         * for PPLive */
        if (match_str_both(data, "\x1c\x1c\x32\x01", "\x1c\x1c\x32\x01"))
                return true;

	if (match_obscure_pplive(data)) {
		return true;
	}


	return false;
}

static lpi_module_t lpi_pplive = {
	LPI_PROTO_UDP_PPLIVE,
	LPI_CATEGORY_P2PTV,
	"PPLive",
	3,
	match_pplive
};

void register_pplive(LPIModuleMap *mod_map) {
	register_protocol(&lpi_pplive, mod_map);
}

