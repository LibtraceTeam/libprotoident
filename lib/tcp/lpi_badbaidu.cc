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

/* Strange flows that seem to be related to users running the Baidu browser.
 * The flow will connect to a Baidu server on port 80, send no data, then
 * start sending FINs. After about 6 FINs, the client will then send a one
 * byte packet with a sequence number matching the original SYN (which is
 * of course completely invalid). At this point, the server usually terminates
 * the connection.
 *
 * Confirmed as being associated with Baidu browser after observing this
 * exact traffic after installing the browser.
 *
 * Not sure what the purpose of this is, or how the browser manages to send
 * invalid TCP traffic but it is the root cause behind a lot of non-HTTP
 * flows on TCP port 80.
 */


static inline bool match_badbaidu(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        /* Only seen on port 80 */
        if (data->client_port != 80 && data->server_port != 80)
                return false;

        /* Packet is one byte; the byte itself is 0x00. The other end
         * does not send any payload.
         */
        if (data->payload_len[0] == 0 && data->payload_len[1] == 1) {
                if (MATCH(data->payload[1], 0x00, 0x00, 0x00, 0x00))
                        return true;
        }

        if (data->payload_len[1] == 0 && data->payload_len[0] == 1) {
                if (MATCH(data->payload[0], 0x00, 0x00, 0x00, 0x00))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_badbaidu = {
	LPI_PROTO_BADBAIDU,
	LPI_CATEGORY_MALWARE,
	"BadBaidu",
	100,
	match_badbaidu
};

void register_badbaidu(LPIModuleMap *mod_map) {
	register_protocol(&lpi_badbaidu, mod_map);
}

