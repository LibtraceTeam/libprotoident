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

static inline bool match_qqd_req(uint32_t payload) {

        if (!MATCH(payload, 0x02, 0x03, ANY, ANY))
                return false;

        if (MATCH(payload, 0x02, 0x03, 0x05, 0x00))
                return true;
        if (MATCH(payload, 0x02, 0x03, 0x05, 0x01))
                return true;
        if (MATCH(payload, 0x02, 0x03, 0x04, 0x00))
                return true;
        if (MATCH(payload, 0x02, 0x03, 0x04, 0x01))
                return true;
        if (MATCH(payload, 0x02, 0x03, 0x04, 0x03))
                return true;
        if (MATCH(payload, 0x02, 0x03, 0x04, 0x06))
                return true;
        return false;
}

static inline bool match_qqd_resp(uint32_t payload) {

        if (MATCH(payload, 0x02, 0x03, 0x04, 0x00))
                return true;
        if (MATCH(payload, 0x02, 0x03, 0x04, 0x04))
                return true;
        if (MATCH(payload, 0x02, 0x03, 0x04, 0x05))
                return true;
        if (MATCH(payload, 0x02, 0x03, 0x04, 0x13))
                return true;
        if (MATCH(payload, 0x02, 0x03, 0x04, 0x17))
                return true;
        if (MATCH(payload, 0x02, 0x03, 0x05, 0x00))
                return true;
        if (MATCH(payload, 0x02, 0x03, 0x05, 0x01))
                return true;
        return false;
}

static inline bool match_qqdownload(lpi_data_t *data, lpi_module_t *mod UNUSED) {


        if ((data->payload[0] & 0xffffff) != (data->payload[1] & 0xffffff))
                return false;

        if (match_qqd_req(data->payload[0])) {
                if (match_qqd_resp(data->payload[1]))
                        return true;
        }

        if (match_qqd_req(data->payload[1])) {
                if (match_qqd_resp(data->payload[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_qqdownload = {
	LPI_PROTO_QQDOWNLOAD,
	LPI_CATEGORY_P2P,
	"QQDownload",
	14,
	match_qqdownload
};

void register_qqdownload(LPIModuleMap *mod_map) {
	register_protocol(&lpi_qqdownload, mod_map);
}

