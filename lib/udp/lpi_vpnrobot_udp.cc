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

static inline bool match_umxw(uint32_t payload) {
        if (MATCH(payload, 'U', 'M', 'X', 'W'))
                return true;
        return false;
}

static inline bool match_robot_fail(uint32_t payload, uint32_t len) {

        if (len == 14) {
                if (MATCH(payload, 0x6d, ANY, ANY, ANY))
                        return true;
        }
        return false;

}

static inline bool match_vpnrobot_udp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_umxw(data->payload[0])) {
                if (match_umxw(data->payload[1]))
                        return true;
                if (match_robot_fail(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_umxw(data->payload[1])) {
                if (match_robot_fail(data->payload[0], data->payload_len[0]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_vpnrobot_udp = {
	LPI_PROTO_UDP_VPNROBOT,
	LPI_CATEGORY_TUNNELLING,
	"VPNRobot",
	15,
	match_vpnrobot_udp
};

void register_vpnrobot_udp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_vpnrobot_udp, mod_map);
}

