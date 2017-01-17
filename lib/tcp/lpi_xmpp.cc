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

static inline bool match_xmpp_payload(uint32_t data, uint32_t len) {

	if (MATCHSTR(data, "<?xm"))
		return true;
	if (MATCHSTR(data, "<str"))
		return true;
	if (MATCHSTR(data, "<pre"))
		return true;

	if (MATCH(data, 0x20, 0x20, 0x20, 0x20) && len == 147)
		return true;
	return false;
}

static inline bool match_xmpp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* If this is overmatching, enforce TCP port 5222 */

	if (!match_xmpp_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_xmpp_payload(data->payload[1], data->payload_len[1]))
		return false;
	

	return true;
}

static lpi_module_t lpi_xmpp = {
	LPI_PROTO_XMPP,
	LPI_CATEGORY_CHAT,
	"XMPP",
	4,
	match_xmpp
};

void register_xmpp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_xmpp, mod_map);
}

