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

static inline bool match_xunlei_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* Require port 3076 for now, as all these rules are based on
         * traffic seen on port 3076 */
        if (data->server_port != 3076 && data->client_port != 3076)
                return false;

        if (match_str_both(data, "\x36\x00\x00\x00", "\x36\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x35\x00\x00\x00", "\x35\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x35\x00\x00\x00", "\x28\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x35\x00\x00\x00", "\x29\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x34\x00\x00\x00", "\x34\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x34\x00\x00\x00", "\x29\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x33\x00\x00\x00", "\x33\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x32\x00\x00\x00", "\x32\x00\x00\x00"))
                return true;

        if (match_str_either(data, "\x36\x00\x00\x00")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }
        if (match_str_either(data, "\x32\x00\x00\x00")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }
        if (match_str_either(data, "\x35\x00\x00\x00")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }
        if (match_str_either(data, "\x34\x00\x00\x00")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }
        if (match_str_either(data, "\x33\x00\x00\x00")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }
        if (match_str_either(data, "\x29\x00\x00\x00")) {
                if (data->payload_len[0] == 0)
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }

	return false;	

	return false;
}

static lpi_module_t lpi_xunlei_udp = {
	LPI_PROTO_UDP_XUNLEI,
	LPI_CATEGORY_P2P,
	"Xunlei_UDP",
	3,
	match_xunlei_udp
};

void register_xunlei_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_xunlei_udp, mod_map);
}

