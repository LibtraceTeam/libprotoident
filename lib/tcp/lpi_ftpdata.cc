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

static inline bool match_bulk_response(uint32_t payload, uint32_t len) {

        /* Most FTP-style transactions result in no packets being sent back
         * to server (aside from ACKs) */

        if (len == 0)
                return true;

        /* However, there is at least one FTP client that sends some sort of
         * sequence number back to the server - maybe allowing for resumption
         * of paused transfers? 
         *
         * XXX This seems to be related to completely failing to implement the
         * FTP protocol correctly. There is usually a flow preceding these
         * flows that sends commands like "get" and "dir" to the server, 
         * which are not actually part of the FTP protocol. Instead, these
         * are often commands typed into FTP CLI clients that are converted
         * into the appropriate FTP commands. No idea what software is doing
         * this, but it is essentially emulating FTP so I'll keep it in here
         * for now.
         * */

        if (len == 4 && MATCH(payload, 0x00, 0x00, 0x02, 0x00))
                return true;
        return false;

}


/* Bulk download covers files being downloaded through a separate channel,
 * like FTP data. We identify these by observing file type identifiers at the
 * start of the packet. This is not a protocol in itself, but it's almost 
 * certainly FTP.
 */
static inline bool match_bulk_download(lpi_data_t *data) {

        if (match_bulk_response(data->payload[1], data->payload_len[1]) &&
                        match_file_header(data->payload[0]))
                return true;
        if (match_bulk_response(data->payload[0], data->payload_len[0]) &&
                        match_file_header(data->payload[1]))
                return true;

        return false;
}

static inline bool match_directory(lpi_data_t *data) {

	/* FTP Data can start with directory permissions */
        if (    (MATCH(data->payload[0], '-', ANY, ANY, ANY) ||
                MATCH(data->payload[0], 'd', ANY, ANY, ANY)) &&
                (MATCH(data->payload[0], ANY, '-', ANY, ANY) ||
                MATCH(data->payload[0], ANY, 'r', ANY, ANY)) &&
                (MATCH(data->payload[0], ANY, ANY, '-', ANY) ||
                MATCH(data->payload[0], ANY, ANY, 'w', ANY)) &&
                (MATCH(data->payload[0], ANY, ANY, ANY, '-') ||
                MATCH(data->payload[0], ANY, ANY, ANY, 'x')) )

                return true;

        if (    (MATCH(data->payload[1], '-', ANY, ANY, ANY) ||
                MATCH(data->payload[1], 'd', ANY, ANY, ANY)) &&
                (MATCH(data->payload[1], ANY, '-', ANY, ANY) ||
                MATCH(data->payload[1], ANY, 'r', ANY, ANY)) &&
                (MATCH(data->payload[1], ANY, ANY, '-', ANY) ||
                MATCH(data->payload[1], ANY, ANY, 'w', ANY)) &&
                (MATCH(data->payload[1], ANY, ANY, ANY, '-') ||
                MATCH(data->payload[1], ANY, ANY, ANY, 'x')) )

                return true;
	return false;
}

static inline bool match_ftp_data(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (match_bulk_download(data))
		return true;
	
	/* XXX All rules below this are for one-way exchanges only */
	if (data->payload_len[0] > 0 && data->payload_len[1] > 0)
                return false;
	
	if (match_directory(data))
		return true;

	/* Virus definition updates from CA are delivered via FTP */
	if (match_str_either(data, "Viru"))
		return true;

	/* XXX - I hate having to look at port numbers but there are no
         * useful headers in FTP data exchanges; all the FTP protocol stuff
         * is done using the control channel */
        if (data->client_port == 20 || data->server_port == 20)
                return true;	

	return false;
}

static lpi_module_t lpi_ftpdata = {
	LPI_PROTO_FTP_DATA,
	LPI_CATEGORY_FILES,
	"FTP_Data",
	5, /* Some of these rules rely on port numbers and one-way data, so
	    * should have a lower priority than more concrete rules */
	match_ftp_data
};

void register_ftpdata(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ftpdata, mod_map);
}

