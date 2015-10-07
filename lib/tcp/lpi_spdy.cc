/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011-2015 The University of Waikato, Hamilton, New Zealand.
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
 * $Id: lpi_spdy.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_spdy_syn(uint32_t payload) {

        if (MATCH(payload, 0x80, 0x03, 0x00, 0x01))
                return true;
        return false;

}

static inline bool match_spdy_settings(uint32_t payload) {

        if (MATCH(payload, 0x80, 0x03, 0x00, 0x04))
                return true;
        return false;

}

static inline bool match_spdy_syn_reply(uint32_t payload) {

        if (MATCH(payload, 0x80, 0x03, 0x00, 0x02))
                return true;
        return false;

}

static inline bool match_spdy(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_spdy_syn(data->payload[0])) {
                if (match_spdy_settings(data->payload[1]))
                        return true;
                if (match_spdy_syn_reply(data->payload[1]))
                        return true;
        }

        if (match_spdy_syn(data->payload[1])) {
                if (match_spdy_settings(data->payload[0]))
                        return true;
                if (match_spdy_syn_reply(data->payload[0]))
                        return true;
        }
	return false;
}

static lpi_module_t lpi_spdy = {
	LPI_PROTO_SPDY,
	LPI_CATEGORY_WEB,
	"SPDY",
	10,
	match_spdy
};

void register_spdy(LPIModuleMap *mod_map) {
	register_protocol(&lpi_spdy, mod_map);
}

