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

static inline bool match_reordered_dns(lpi_data_t *data) {

        /* Unfortunately, UDP can get reordered so if there are multiple
         * queries in a flow we cannot guarantee that the first response
         * will have the same ID as the first query.
         */


        /* Just try and match common request / response flag arrangements */
        if (MATCH(data->payload[0], ANY, ANY, 0x01, 0x00)) {
                if (MATCH(data->payload[1], ANY, ANY, 0x81, 0x80))
                        return true;
        }

        if (MATCH(data->payload[1], ANY, ANY, 0x01, 0x00)) {
                if (MATCH(data->payload[0], ANY, ANY, 0x81, 0x80))
                        return true;
        }

        return false;


}

static inline bool match_dns_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* As loath as I am to do this, we probably shouldn't allow any DNS
	 * on ports other than 53 */
	if (data->server_port != 53 && data->client_port != 53)
		return false;

	if (match_dns(data))
		return true;

        if (match_reordered_dns(data))
                return true;

	return false;
}

static lpi_module_t lpi_dns_udp = {
	LPI_PROTO_UDP_DNS,
	LPI_CATEGORY_SERVICES,
	"DNS",
	10,	/* Not a high certainty */
	match_dns_udp
};

void register_dns_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_dns_udp, mod_map);
}

