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
#include <stdio.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* Some sort of phone-home protocol mostly used by QQPCMgr, a "security"
 * program by QQ.
 *
 * Appears to occasionally be used by other QQ background processes, like
 * QQLive, but the background processes created by QQPCMgr uses this 
 * protocol far more than anything else I've seen.
 */

static inline bool match_qqpcmgr(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->server_port != 8000 && data->client_port != 8000)
	    return false;
	
	if (!MATCH(data->payload[0], 0x00, 0x02, 0x00, ANY))
	    return false;
	if (!MATCH(data->payload[1], 0x00, 0x02, 0x00, ANY))
	    return false;

	/* Usually byte 4 matches for both payloads, but not always */

        return true;
}

static lpi_module_t lpi_qqpcmgr = {
	LPI_PROTO_UDP_QQPCMGR,
	LPI_CATEGORY_SECURITY,
	"QQPCMgr",
	21,
	match_qqpcmgr
};

void register_qqpcmgr(LPIModuleMap *mod_map) {
	register_protocol(&lpi_qqpcmgr, mod_map);
}

