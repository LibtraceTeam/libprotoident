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

static inline bool match_ssh2_payload(uint32_t payload, uint32_t len) {

        /* SSH-2 begins with a four byte length field */


        if (len == 0)
                return true;
        
	/* DON'T BYTESWAP!!! */
	if (payload == len)
                return true;
        return false;

}

static inline bool match_ssh(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_str_either(data, "SSH-"))
                return true;

        /* Require port 22 for the following rules as they are not
         * specific to SSH */
        if (data->server_port != 22 && data->client_port != 22)
                return false;
        if (match_str_either(data, "QUIT"))
                return true;


       	if (!match_ssh2_payload(data->payload[0], data->payload_len[0])) 
		return false;

        if (!match_ssh2_payload(data->payload[1], data->payload_len[1])) 
              	return false;
        

        return true;

}

static lpi_module_t lpi_ssh = {
	LPI_PROTO_SSH,
	LPI_CATEGORY_REMOTE,
	"SSH",
	2,
	match_ssh
};

void register_ssh(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ssh, mod_map);
}

