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

/* This one is a bit tenuous but I'm reasonably confident that this is
 * something to do with the Dell backup and recovery service. All observed
 * traffic matching the rules described here go 66.151.242.0/24, which has
 * previously reversed to dellbackupandrecoverycloudstorage.com.
 */

static inline bool match_dell_backup_req(uint32_t payload, uint32_t len) {
        if (len != 12)
                return false;
        if (MATCH(payload, 0x08, 0x00, 0x00, 0x00))
                return true;
        return false;

}

static inline bool match_dell_backup_resp(uint32_t payload, uint32_t len) {
        if (len != 24)
                return false;
        if (MATCH(payload, 0x14, 0x00, 0x00, 0x00))
                return true;
        return false;

}

static inline bool match_dell_backup(lpi_data_t *data, lpi_module_t *mod UNUSED) {
        if (data->server_port != 443 && data->client_port != 443)
                return false;

        if (match_dell_backup_req(data->payload[0], data->payload_len[0])) {
                if (match_dell_backup_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_dell_backup_req(data->payload[1], data->payload_len[1])) {
                if (match_dell_backup_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }
        
	return false;
}

static lpi_module_t lpi_dell_backup = {
	LPI_PROTO_DELL_BACKUP,
	LPI_CATEGORY_CLOUD,
	"DellBackup",
	100,
	match_dell_backup
};

void register_dell_backup(LPIModuleMap *mod_map) {
	register_protocol(&lpi_dell_backup, mod_map);
}

