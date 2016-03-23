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

static inline bool check_length(uint32_t payload, uint32_t len) {
	uint16_t *lenptr;
	uint32_t swap;
	
	uint32_t length;

	if (!(MATCH(payload, ANY, ANY, 0x02, ANY) || 
			MATCH(payload, ANY, ANY, 0x2d, ANY)))
		return false;
	
	swap=ntohl(payload);

	length = swap >> 16;

	if (length != len)
		return false;
	return true;

}

static inline bool match_qq_8080(uint32_t payload, uint32_t len) {
        if (len == 0)
                return false;

        if (ntohl(payload) == len)
                return true;
        return false;
}

static inline bool match_qq_tcp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->server_port == 8080 || data->client_port == 8080) {
                /* Typically traffic to msfwifi.3g.qq.com, only seen on
                 * mobile QQ clients.
                 */

                if (match_qq_8080(data->payload[0], data->payload_len[0])) {
                        if (match_qq_8080(data->payload[1], data->payload_len[1]))
                                return true;
                }

        }


	if (data->payload_len[0] == 0 || data->payload_len[1] == 0)
		return false;
	if ((data->payload[0] & 0xffff0000) != (data->payload[1] & 0xffff0000))
		return false;
	
	if ((data->payload[0] & 0xffff0000) ==  0x00000000)
		return false;
	if ((data->payload[1] & 0xffff0000) ==  0x00000000)
		return false;
	
	if (!check_length(data->payload[0], data->payload_len[0]))
		return false;

	if (!check_length(data->payload[1], data->payload_len[1]))
		return false;
	

	return true;
}

static lpi_module_t lpi_qq_tcp = {
	LPI_PROTO_QQ,
	LPI_CATEGORY_CHAT,
	"QQ",
	20,
	match_qq_tcp
};

void register_qq_tcp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_qq_tcp, mod_map);
}

