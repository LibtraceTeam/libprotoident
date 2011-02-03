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

static inline bool match_dc(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* $MyN seemed best to check for - might have to check for $max and
	 * $Sup as well */
	/* NOTE: Some people seem to use DC to connect to port 80 and get
	 * HTTP responses. At this stage, I'd rather that fell under DC rather
	 * than HTTP, so we need to check for this before we check for HTTP */


	if (match_str_either(data, "$MyN")) return true;
	if (match_str_either(data, "$Sup")) return true;
	if (match_str_either(data, "$Loc")) return true;

	/* Response is usually an HTTP response - we could check that if
	 * needed */
	
	return false;

}

static lpi_module_t lpi_directconnect = {
	LPI_PROTO_DC,
	LPI_CATEGORY_P2P,
	"DirectConnect",
	1, /* Need a higher priority than regular HTTP */
	match_dc
};

void register_directconnect(LPIModuleMap *mod_map) {
	register_protocol(&lpi_directconnect, mod_map);
}

