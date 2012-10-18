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
 * $Id: lpi_whois.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_dot_second(uint32_t payload) {
	if (MATCH(payload, ANY, '.', ANY, ANY))
		return true;
	return false;
}

static inline bool match_dot_third(uint32_t payload) {
	if (MATCH(payload, ANY, ANY, '.', ANY))
		return true;
	return false;
}

static inline bool match_dot_last(uint32_t payload) {
	if (MATCH(payload, ANY, ANY, ANY, '.'))
		return true;
	return false;
}

static inline bool match_digit_first(uint32_t payload) {

	if (MATCH(payload, '1', ANY, ANY, ANY))
		return true;
	if (MATCH(payload, '2', ANY, ANY, ANY))
		return true;
	if (MATCH(payload, '3', ANY, ANY, ANY))
		return true;
	if (MATCH(payload, '4', ANY, ANY, ANY))
		return true;
	if (MATCH(payload, '5', ANY, ANY, ANY))
		return true;
	if (MATCH(payload, '6', ANY, ANY, ANY))
		return true;
	if (MATCH(payload, '7', ANY, ANY, ANY))
		return true;
	if (MATCH(payload, '8', ANY, ANY, ANY))
		return true;
	if (MATCH(payload, '9', ANY, ANY, ANY))
		return true;
	if (MATCH(payload, '0', ANY, ANY, ANY))
		return true;
	return false;
}

static inline bool match_digit_second(uint32_t payload) {

	if (MATCH(payload, ANY, '1', ANY, ANY))
		return true;
	if (MATCH(payload, ANY, '2', ANY, ANY))
		return true;
	if (MATCH(payload, ANY, '3', ANY, ANY))
		return true;
	if (MATCH(payload, ANY, '4', ANY, ANY))
		return true;
	if (MATCH(payload, ANY, '5', ANY, ANY))
		return true;
	if (MATCH(payload, ANY, '6', ANY, ANY))
		return true;
	if (MATCH(payload, ANY, '7', ANY, ANY))
		return true;
	if (MATCH(payload, ANY, '8', ANY, ANY))
		return true;
	if (MATCH(payload, ANY, '9', ANY, ANY))
		return true;
	if (MATCH(payload, ANY, '0', ANY, ANY))
		return true;
	return false;
}

static inline bool match_digit_third(uint32_t payload) {

	if (MATCH(payload, ANY, ANY, '1', ANY))
		return true;
	if (MATCH(payload, ANY, ANY, '2', ANY))
		return true;
	if (MATCH(payload, ANY, ANY, '3', ANY))
		return true;
	if (MATCH(payload, ANY, ANY, '4', ANY))
		return true;
	if (MATCH(payload, ANY, ANY, '5', ANY))
		return true;
	if (MATCH(payload, ANY, ANY, '6', ANY))
		return true;
	if (MATCH(payload, ANY, ANY, '7', ANY))
		return true;
	if (MATCH(payload, ANY, ANY, '8', ANY))
		return true;
	if (MATCH(payload, ANY, ANY, '9', ANY))
		return true;
	if (MATCH(payload, ANY, ANY, '0', ANY))
		return true;
	return false;
}

static inline bool match_digit_last(uint32_t payload) {

	if (MATCH(payload, ANY, ANY, ANY, '1'))
		return true;
	if (MATCH(payload, ANY, ANY, ANY, '2'))
		return true;
	if (MATCH(payload, ANY, ANY, ANY, '3'))
		return true;
	if (MATCH(payload, ANY, ANY, ANY, '4'))
		return true;
	if (MATCH(payload, ANY, ANY, ANY, '5'))
		return true;
	if (MATCH(payload, ANY, ANY, ANY, '6'))
		return true;
	if (MATCH(payload, ANY, ANY, ANY, '7'))
		return true;
	if (MATCH(payload, ANY, ANY, ANY, '8'))
		return true;
	if (MATCH(payload, ANY, ANY, ANY, '9'))
		return true;
	if (MATCH(payload, ANY, ANY, ANY, '0'))
		return true;
	return false;
}

static inline bool match_ipv4_text(uint32_t payload) {

	bool seen_dot = false;

	/* Gotta start with a digit */
	if (!match_digit_first(payload))
		return false;

	/* Matching the case 1.XX */
	if (match_dot_second(payload)) {
		/* Can't have two dots in a row */
		if (!match_digit_third(payload))
			return false;

		/* We can have either two digits, e.g. 1.45 */
		if (match_digit_last(payload))
			return true;
		/* Or a another dot, e.g. 1.1. */
		if (match_dot_last(payload))
			return true;
		return false;
	} 
	
	/* Not a dot so must be a digit, e.g. 11XX */
	if (!match_digit_second(payload)) {
		return false;
	}

	/* If the third character is a dot, then we need a digit as the last
	 * e.g. 10.4 */
	if (match_dot_third(payload)) {
		if (!match_digit_last(payload))
			return false;
		return true;
	} 

	/* Third character must be a digit, then */
	if (!match_digit_third(payload))
		return false;

	/* If we've got three digits, we must end on a dot - e.g. 192. */
	if (match_dot_last(payload))
		return true;

	return false;
}

static inline bool match_md5_option(uint32_t payload) {

	if (MATCHSTR(payload, "-V M"))
		return true;
	return false;

}

static inline bool match_whois(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (data->server_port != 43 && data->client_port != 43)
		return false;

	if (match_ipv4_text(data->payload[0])) {
		if (data->payload_len[0] >= 4)
			return true;
	}

	if (match_md5_option(data->payload[0]))
		return true;

	if (match_ipv4_text(data->payload[1])) {
		if (data->payload_len[1] >= 4)
			return true;
	}
	if (match_md5_option(data->payload[1]))
		return true;
	return false;
}

static lpi_module_t lpi_whois = {
	LPI_PROTO_WHOIS,
	LPI_CATEGORY_SERVICES,
	"Whois",
	20,
	match_whois
};

void register_whois(LPIModuleMap *mod_map) {
	register_protocol(&lpi_whois, mod_map);
}

