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
 * $Id$
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_smb_payload(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;

        if (match_payload_length(payload, len))
                return true;

        /* Some stupid systems send the NetBIOS header separately, which
         * makes this a lot harder to detect :( 
         *
         * Instead, look for common payload sizes. */

        if (MATCH(payload, 0x00, 0x00, 0x00, 0x85))
                return true;

        /* Also, sometimes we just forget the NetBIOS header, or the 
         * connection fails before it is retransmitted */
        if (MATCH(payload, 0xff, 'S', 'M', 'B'))
                return true;

        return false;

}


static inline bool match_smb(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	/* SMB is often prepended with a NetBIOS session service header.
         * It's easiest for us to treat it as a four byte length field (it
         * is actually a bit more complicated than that, but all other fields
         * tend to be zero anyway)
         *
         * More details at http://lists.samba.org/archive/samba-technical/2003-January/026283.html
         */

	/* Only match on port 445 to avoid clashing with other 4 byte length
	 * fields */
        if (data->server_port != 445 && data->client_port != 445)
                return false;

        if (!match_smb_payload(data->payload[0], data->payload_len[0]))
                return false;

        if (!match_smb_payload(data->payload[1], data->payload_len[1]))
                return false;
        return true;


}

extern "C"
lpi_module_t * lpi_register() {
	
	lpi_module_t *mod = new lpi_module_t;

	mod->protocol = LPI_PROTO_SMB;
	strncpy(mod->name, "SMB", 255);
	mod->category = LPI_CATEGORY_FILES;
	
	/* The port number req means we can trust this rule more than other
	 * 4 byte length matches */
	mod->priority = 2; 	
	mod->dlhandle = NULL;
	mod->lpi_callback = match_smb;

	return mod;

}
