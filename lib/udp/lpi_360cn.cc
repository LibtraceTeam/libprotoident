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

/* Not 100% sure what this is but:
 *  - it's on port 53 but is definitely not DNS
 *  - involves servers owned by 360.cn, who 'supposedly' are antivirus experts
 *  - most of these same servers are contacted by various known malware, 
      particularly Zegost variants
 *  - the protocol appears to be a custom encryption protocol
 *
 * In all likelihood, this is the C&C protocol for some nasty Chinese backdoor.
 */


static inline bool match_360cn_0102(uint32_t a, uint32_t b) {


        if (a != b)
                return false;
        if (MATCH(a, ANY, ANY, 0x01, 0x02))
                return true;
        return false;

}

static inline bool match_360cn_0a04(uint32_t pload, uint32_t len) {

        uint32_t hdrlen = (ntohl(pload)) & 0xffff;

        if (len == 0)
                return true;

        if (!MATCH(pload, 0x0a, 0x04, ANY, ANY))
                return false;

        if (hdrlen + 10 == len)
                return true;

        return false;


}

static inline bool match_360cn(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->server_port != 53 && data->client_port != 53)
                return false;
        
        if (match_360cn_0102(data->payload[0], data->payload[1]))
                return true;

        if (match_360cn_0a04(data->payload[0], data->payload_len[0])) {
                if (match_360cn_0a04(data->payload[1], data->payload_len[1]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_360cn = {
	LPI_PROTO_360CN,
	LPI_CATEGORY_MALWARE,
	"360.cn",
	50,
	match_360cn
};

void register_360cn(LPIModuleMap *mod_map) {
	register_protocol(&lpi_360cn, mod_map);
}

