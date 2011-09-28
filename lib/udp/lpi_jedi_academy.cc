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

static inline bool match_jedi_academy(lpi_data_t *data, 
		lpi_module_t *mod UNUSED) {

	/* Pretty rare, but we can write a rule for it */
        if (match_str_both(data, "\xff\xff\xff\xff", "\xff\xff\xff\xff")) {
                /* Server browsing */
                if (data->payload_len[0] == 65 && data->payload_len[1] == 181)
                        return true;
                if (data->payload_len[0] == 66 && data->payload_len[1] == 182)
                        return true;
                if (data->payload_len[1] == 65 && data->payload_len[0] == 181)
                        return true;
                if (data->payload_len[1] == 66 && data->payload_len[0] == 182)
                        return true;

                /* Actual gameplay */
                if (data->payload_len[0] == 16 && data->payload_len[1] == 32)
                        return true;
                if (data->payload_len[1] == 16 && data->payload_len[0] == 32)
                        return true;
        }


	return false;
}

static lpi_module_t lpi_jedi = {
	LPI_PROTO_UDP_JEDI_ACADEMY,
	LPI_CATEGORY_GAMING,
	"JediAcademy",
	5,
	match_jedi_academy
};

void register_jedi_academy(LPIModuleMap *mod_map) {
	register_protocol(&lpi_jedi, mod_map);
}

