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

static inline bool match_invalid(lpi_data_t *data, lpi_module_t *mod UNUSED) {
	
	/* I'm using invalid as a category for flows where both halves of
         * the connection are clearly speaking different protocols,
         * e.g. trying to do HTTP tunnelling via an SMTP server
         */

        /* XXX Bittorrent-related stuff is covered in 
         * match_invalid_bittorrent() */

        /* SOCKSv4 via FTP or SMTP 
         *
         * The last two octets '\x00\x50' is the port number - in this case
         * I've hard-coded it to be 80 */
        if (match_str_both(data, "220 ", "\x04\x01\x00\x50"))
                return true;

        /* SOCKSv5 via FTP or SMTP */
        if (match_str_both(data, "220 ", "\x05\x01\x00\x00"))
                return true;

        /* HTTP tunnelling via FTP or SMTP */
        if (match_str_both(data, "220 ", "CONN"))
                return true;
        if (match_str_both(data, "450 ", "CONN"))
                return true;

        /* Trying to send HTTP commands to FTP or SMTP servers */
        if (match_str_both(data, "220 ", "GET "))
                return true;
        if (match_str_both(data, "450 ", "GET "))
                return true;

        /* Trying to send HTTP commands to an SVN server */
        if (match_str_both(data, "( su", "GET "))
                return true;

        /* People running an HTTP server on the MS SQL server port */
        if (match_tds_request(data->payload[0], data->payload_len[0])) {
                if (MATCHSTR(data->payload[1], "HTTP"))
                        return true;
        }
        if (match_tds_request(data->payload[1], data->payload_len[1])) {
                if (MATCHSTR(data->payload[0], "HTTP"))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_invalid = {
	LPI_PROTO_INVALID,
	LPI_CATEGORY_MIXED,
	"Invalid",
	200,	/* Very low priority, but not as low as mystery protos */
	match_invalid
};

void register_invalid(LPIModuleMap *mod_map) {
	register_protocol(&lpi_invalid, mod_map);
}

