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
 * $Id: lpi_qvod.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* Chinese variant of BitTorrent -- www.qvod.com */

static inline bool match_qvod_message(uint32_t payload, uint32_t len) {

        if (!MATCH(payload, 0x13, 'Q', 'V', 'O'))
                return false;
        if (len != 68)
                return false;
        return true;

}

static inline bool match_qvod(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_qvod_message(data->payload[0], data->payload_len[0])) {
                if (match_qvod_message(data->payload[1], data->payload_len[1]))
                        return true;
                if (data->payload_len[1] == 0)
                        return true;
        }

        if (match_qvod_message(data->payload[1], data->payload_len[1])) {
                if (match_qvod_message(data->payload[0], data->payload_len[0]))
                        return true;
                if (data->payload_len[0] == 0)
                        return true;
        }

	return false;
}

static lpi_module_t lpi_qvod = {
	LPI_PROTO_QVOD,
	LPI_CATEGORY_P2P,
	"Qvod",
	6,
	match_qvod
};

void register_qvod(LPIModuleMap *mod_map) {
	register_protocol(&lpi_qvod, mod_map);
}

