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

static inline bool match_warcraft3(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_chars_either(data, 0xf7, 0x37, 0x12, 0x00))
		return true;

        /* XXX - I have my doubts about these rules */
#if 0   
        /* Warcraft 3 packets all begin with 0xf7 */
        if (match_chars_either(proto_d, 0xf7, 0xf7, ANY, ANY)) 
                return LPI_PROTO_WARCRAFT3;
        /* Another Warcraft 3 example added by Donald Neal */
        if (match_chars_either(proto_d, 0xf7, 0x1e, ANY, 0x00))
                return LPI_PROTO_WARCRAFT3;
#endif
	

	return false;
}

static lpi_module_t lpi_warcraft3 = {
	LPI_PROTO_WARCRAFT3,
	LPI_CATEGORY_GAMING,
	"Warcraft3",
	5, /* I'm a bit dubious about the value of this rule */
	match_warcraft3
};

void register_warcraft3(LPIModuleMap *mod_map) {
	register_protocol(&lpi_warcraft3, mod_map);
}

