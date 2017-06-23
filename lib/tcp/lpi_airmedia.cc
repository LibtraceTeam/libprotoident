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

/* Crestron Airmedia -- more details at:
 * http://www.boredhackerblog.info/2016/02/extracting-images-from-crestron.html
 */

static inline bool match_cam_wppi(uint32_t payload, uint32_t len) {
        if (len == 12 && MATCHSTR(payload, "wppi"))
                return true;
        return false;
}

static inline bool match_cam_sender(uint32_t payload, uint32_t len) {
        if (len == 32 && MATCHSTR(payload, "Send"))
                return true;
        return false;
}

static inline bool match_airmedia(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Port 515 */
        if (match_cam_wppi(data->payload[0], data->payload_len[0])) {
                if (match_cam_sender(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_cam_wppi(data->payload[1], data->payload_len[1])) {
                if (match_cam_sender(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_airmedia = {
	LPI_PROTO_AIRMEDIA,
	LPI_CATEGORY_REMOTE,
	"Airmedia",
	5,
	match_airmedia
};

void register_airmedia(LPIModuleMap *mod_map) {
	register_protocol(&lpi_airmedia, mod_map);
}

