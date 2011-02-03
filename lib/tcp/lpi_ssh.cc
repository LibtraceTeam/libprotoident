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

static inline bool match_ssh2_payload(uint32_t payload, uint32_t len) {

        /* SSH-2 begins with a four byte length field */

        if (len == 0)
                return true;
        if (ntohl(payload) == len)
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

        if (match_ssh2_payload(data->payload[0], data->payload_len[0])) {
                if (match_ssh2_payload(data->payload[1], data->payload_len[1]))
                        return true;
        }
        if (match_ssh2_payload(data->payload[1], data->payload_len[1])) {
                if (match_ssh2_payload(data->payload[0], data->payload_len[0]))
                        return true;
        }

        return false;

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

