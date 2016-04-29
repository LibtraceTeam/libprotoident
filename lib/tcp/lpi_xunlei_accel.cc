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
 * $Id$
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"


/* This protocol is definitely tied up with Xunlei. It appears to only be
 * used when using the "accelerated" download option in the Thunder client.
 * Basically, the download will be accelerated by pulling parts of the content
 * from servers owned by Xunlei in addition to the standard P2P downloading
 * from other Xunlei users.
 *
 * Not 100% sure this should be a separate protocol, but the distinction
 * compared with the other Xunlei stuff is possibly interesting.
 */

/* NOTE: we see a lot of other xunlei traffic with a similar payload pattern
 * on other ports but the payload sizes don't match up so I suspect this is
 * 'other' thunder traffic of some sort.
 */

static inline bool match_xaccel_req(uint32_t payload, uint32_t len) {

        uint32_t byte4;
        /* Byte 4 must be either 0x4X or 0x5X */
        
        byte4 = (ntohl(payload) & 0xff);

        if (byte4 < 0x40 || byte4 > 0x5f)
                return false;

        /* Observed requests seem to fall in a very specific packet size
         * range (at least the stuff on port 8080 does) 
         */
        if (len >= 532 && len <= 542)
                return true;
        if (len >= 309 && len <= 312)
                return true;

        return false;
}

static inline bool match_xaccel_resp(uint32_t payload, uint32_t len) {

        uint32_t byte4;
        /* Byte 4 must be either 0x4X or 0x5X */
        
        byte4 = (ntohl(payload) & 0xff);

        if (byte4 < 0x40 || byte4 > 0x5f)
                return false;

        /* Observed requests seem to fall in a very specific packet size
         * range (at least the stuff on port 8080 does) 
         */
        if (len >= 104 && len <= 116)
                return true;

        return false;
}

static inline bool match_xunlei_accel(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Tough to match reliably -- we don't have a lot to go on */

        /* The Xunlei-controlled servers all seem to listen on port 8080 */
        if (data->server_port != 8080 && data->client_port != 8080)
                return false;

        if (match_xaccel_req(data->payload[0], data->payload_len[0])) {
                if (match_xaccel_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_xaccel_req(data->payload[1], data->payload_len[1])) {
                if (match_xaccel_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_xunlei_accel = {
	LPI_PROTO_XUNLEI_ACCEL,
	LPI_CATEGORY_P2P,
	"XunleiAccelerated",
	240,
	match_xunlei_accel
};

void register_xunlei_accel(LPIModuleMap *mod_map) {
	register_protocol(&lpi_xunlei_accel, mod_map);
}

