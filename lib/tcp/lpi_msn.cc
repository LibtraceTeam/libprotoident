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

static inline bool match_msn(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_str_either(data, "ANS "))
		return true;
	if (match_str_either(data, "USR "))
		return true;
	if (match_str_either(data, "VER "))
		return true;

	return false;
}

extern "C"
lpi_module_t * lpi_register() {
	
	lpi_module_t *mod = new lpi_module_t;

	mod->protocol = LPI_PROTO_MSN;
	strncpy(mod->name, "MSN", 255);
	mod->category = LPI_CATEGORY_CHAT;
	mod->priority = 2; 	
	mod->dlhandle = NULL;
	mod->lpi_callback = match_msn;

	return mod;

}
