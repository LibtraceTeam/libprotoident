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
 * $Id: lpi_revolver_nblbt.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* This appears to be some sort of Chinese P2P game updating software from
 * Revolver Software (?).
 * 
 * This is based on the appearance of the strings "nblbt" and "nbmep" in
 * the payload of the initial packets. NBLBT.rar and NBMEP.rar can be 
 * downloaded from www.zy995.com which seems to host numerous offerings from
 * Revolver Software. 
 *
 * Yet to fully confirm as a) I don't know enough Chinese to install and run
 * the software sensibly and b) I strongly suspect the software is bundled
 * with all sorts of malware so am reluctant to install it anywhere that isn't
 * a completely fenced-off sandbox.
 */

static inline bool match_nblbt_ok(uint32_t payload, uint32_t len) {
        if (len != 20)
                return false;
        if (!MATCH(payload, 'o', 'k', 0x00, 0x00))
                return false;
        return true;

}

static inline bool match_nblbt_reply(uint32_t payload, uint32_t len) {
        if (len == 0)
                return true;
        if (len != 1024)
                return false;
        if (!MATCH(payload, 0x00, 0x00, 0x00, 0x00))
                return false;
        return true;

}

static inline bool match_revolver_nblbt(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_nblbt_ok(data->payload[0], data->payload_len[0])) {
                if (match_nblbt_reply(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_nblbt_ok(data->payload[1], data->payload_len[1])) {
                if (match_nblbt_reply(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_revolver_nblbt = {
	LPI_PROTO_REVOLVER_NBLBT,
	LPI_CATEGORY_P2P,
	"RevolverNBLBT",
	6,
	match_revolver_nblbt
};

void register_revolver_nblbt(LPIModuleMap *mod_map) {
	register_protocol(&lpi_revolver_nblbt, mod_map);
}

