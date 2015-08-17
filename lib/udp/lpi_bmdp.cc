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
 * $Id: lpi_bmdp.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>
#include <stdio.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* BMDP is a protocol used by Microsoft Automated Deployment Services, a
 * system for remotely installing, configuring and maintained Windows Servers.
 *
 * Unfortunately, there is no obvious BMDP spec out there so this is just
 * based on what we have seen in our traffic.
 */

static inline bool match_bmdp_payload(uint32_t payload, uint32_t len) {
        uint32_t byte3 = ntohl(payload) & 0xff00;
        uint32_t byte4 = ntohl(payload) & 0x00ff;

        if (len == 0)
                return false;

        printf("%08x %08x\n", byte3, byte4);
        /* Byte 3 is always Xd, where X >=0 and X < 8 */
        if ((ntohl(payload) & 0x7d00) != byte3)
                return false;

        /* There seem to be a fixed set of values for byte 4 and these seem
         * to also determine the length.
         *
         * So far I've limited this to byte4's that I've seen on multiple
         * occasions.
         */
        if (byte4 == 0x2d && (len == 115 || len == 114))
                return true;

        if (byte4 == 0x42 && len == 116)
                return true;

        if (byte4 == 0x5c && len == 117)
                return true;

        return false;
}

static inline bool match_bmdp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* XXX The typical port number is 8197, but usually you will see this
         * on a port ranging from 8190 to 8210. We could consider limiting
         * this rule to traffic matching those ports if we really wanted.
         */

        /* Traffic is always one-way only */
        if (data->payload_len[0] != 0 && data->payload_len[1] != 0)
                return false;

        if (match_bmdp_payload(data->payload[0], data->payload_len[0]))
                return true;

        if (match_bmdp_payload(data->payload[1], data->payload_len[1]))
                return true;

	return false;
}

static lpi_module_t lpi_bmdp = {
	LPI_PROTO_UDP_BMDP,
	LPI_CATEGORY_FILES,
	"BMDP",
	70,
	match_bmdp
};

void register_bmdp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_bmdp, mod_map);
}

