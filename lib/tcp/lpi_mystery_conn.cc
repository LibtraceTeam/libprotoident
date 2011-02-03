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

static inline bool match_mystery_conn(lpi_data_t *data, lpi_module_t *mod UNUSED) {
	/* Appears to be some sort of file transfer protocol, but
         * trying to google for a protocol using words such as "connect"
         * and "receive" is not very helpful */

        if (match_str_both(data, "conn", "reci"))
                return true;

        if (match_str_either(data, "reci")) {
                if (data->payload_len[1] == 0)
                        return true;
                if (data->payload_len[0] == 0)
                        return true;
        }


	return false;
}

static lpi_module_t lpi_mystery_conn = {
	LPI_PROTO_MYSTERY_CONN,
	LPI_CATEGORY_NO_CATEGORY,
	"Mystery_conn",
	250,
	match_mystery_conn
};

void register_mystery_conn(LPIModuleMap *mod_map) {
	register_protocol(&lpi_mystery_conn, mod_map);
}

