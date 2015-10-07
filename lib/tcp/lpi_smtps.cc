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

static inline bool match_smtps(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* This rule matches legacy secure SMTP - this stuff shouldn't
	 * really exist anymore... */

	if (!match_ssl(data))
		return false;
	
	/* Secure SMTP uses port 465 */
	if (data->server_port != 465 && data->client_port != 465)
		return false;

	return true;
}

static lpi_module_t lpi_smtps = {
	LPI_PROTO_SMTPS,
	LPI_CATEGORY_MAIL,
	"SMTP_Secure",
	5, /* Should be a higher priority than regular SSL */
	match_smtps
};

void register_smtps(LPIModuleMap *mod_map) {
	register_protocol(&lpi_smtps, mod_map);
}

