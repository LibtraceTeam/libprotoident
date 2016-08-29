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


static inline bool match_nobu_rand(uint32_t payload, uint32_t len) {

        /* This seems to be a random host-specific ID? */

        /* Rule out 00000000, as that is unlikely to be this */
        if (MATCH(payload, 0x00, 0x00, 0x00, 0x00))
                return false;

        if (len == 4)
                return true;
        return false;
}

static inline bool match_nobu_zeroes(uint32_t payload, uint32_t len) {

        if (len != 4)
                return false;

        if (MATCH(payload, 0x00, 0x00, 0x00, 0x00))
                return true;
        if (MATCH(payload, 0x01, 0x00, 0x00, 0x00))
                return true;
        if (MATCH(payload, 0x02, 0x00, 0x00, 0x00))
                return true;
        if (MATCH(payload, 0x03, 0x00, 0x00, 0x00))
                return true;

        return false;
}

static inline bool match_norton_backup(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->server_port != 80 && data->client_port != 80)
                return false;

        /* Some sort of keep-alive protocol? Appears regularly on machines with
         * Norton backup active, but generally only sends 4 bytes each way.
         */
        if (match_nobu_rand(data->payload[0], data->payload_len[0])) {
                if (match_nobu_zeroes(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_nobu_rand(data->payload[1], data->payload_len[1])) {
                if (match_nobu_zeroes(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_norton_backup = {
	LPI_PROTO_NORTON_BACKUP,
	LPI_CATEGORY_CLOUD,
	"NortonBackup",
	25,
	match_norton_backup
};

void register_norton_backup(LPIModuleMap *mod_map) {
	register_protocol(&lpi_norton_backup, mod_map);
}

