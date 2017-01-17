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

static inline bool match_socks_response(uint32_t payload, uint32_t len) {

	if (len == 3 && MATCH(payload, 0x05, 0x01, 0x00, 0x00))
		return true;
	if (len == 9 && MATCH(payload, 0x04, 0x01, 0x00, 0x19))
		return true;
	return false;

}

static inline bool match_trojan_request(uint32_t payload, uint32_t len) {

	/* This is the typical request packet sent to the SOCKS server
	 * that the infected machines connect to */
	if (len != 5)
		return false;
	if (!MATCH(payload, ANY, ANY, 0x00, 0x00))
		return false;
	return true;
}

static inline bool match_trojan_other(uint32_t payload, uint32_t len) {

	/* Occasionally, the infected machine and the SOCKS server
	 * exchange packets that have this payload */
	if (!MATCH(payload, 0x01, 0x38, 0x71, 0x74)) 
		return false;

	return true;

}

static inline bool match_trojan_win32_generic_sb(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->server_port != 3000 && data->client_port != 3000)
		return false;

	if (match_trojan_other(data->payload[0], data->payload_len[0])) {
		if (match_trojan_other(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_socks_response(data->payload[0], data->payload_len[0])) {
		if (match_trojan_request(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_socks_response(data->payload[1], data->payload_len[1])) {
		if (match_trojan_request(data->payload[0], data->payload_len[0]))
			return true;
	}
	return false;
}

static lpi_module_t lpi_trojan_win32_generic_sb = {
	LPI_PROTO_TROJAN_WIN32_GENERIC_SB,
	LPI_CATEGORY_MALWARE,
	"Trojan.Win32.Generic!SB",
	10,
	match_trojan_win32_generic_sb
};

void register_trojan_win32_generic_sb(LPIModuleMap *mod_map) {
	register_protocol(&lpi_trojan_win32_generic_sb, mod_map);
}

