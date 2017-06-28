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

/* Interactive Live Video Broadcasting, a service offered by Tencent QCloud.
 *
 * Seems to be some sort of SDK for developing live streaming applications.
 */

static inline bool match_qcloud_ilvb(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Packet sizes can vary -- 51,53,55,68 observed */
        if (MATCH(data->payload[0], 0x28, 0x00, 0x00, 0x00)) {
                if (MATCH(data->payload[1], 0x28, 0x00, 0x00, 0x00))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_qcloud_ilvb = {
	LPI_PROTO_QCLOUD_ILVB,
	LPI_CATEGORY_STREAMING,
	"QCloud_ILVB",
	199,
	match_qcloud_ilvb
};

void register_qcloud_ilvb(LPIModuleMap *mod_map) {
	register_protocol(&lpi_qcloud_ilvb, mod_map);
}

