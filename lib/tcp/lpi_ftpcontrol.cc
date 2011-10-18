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

static inline bool match_ftp_reply_code(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;

        if (MATCHSTR(payload, "220 "))
                 return true;
        if (MATCHSTR(payload, "220-"))
                 return true;
        return false;
}

static inline bool match_ftp_command(uint32_t payload, uint32_t len) {

        if (len == 0)
                return true;
        /* There are lots of valid FTP commands, but let's just limit this
         * to ones we've observed for now */

        if (MATCHSTR(payload, "USER"))
                return true;
        if (MATCHSTR(payload, "QUIT"))
                return true;
        if (MATCHSTR(payload, "FEAT"))
                return true;
        if (MATCHSTR(payload, "HELP"))
                return true;
        if (MATCHSTR(payload, "user"))
                return true;

        /* This is invalid syntax, but clients using HOST seem to revert to
         * sane FTP commands once the server reports a syntax error */
        if (MATCHSTR(payload, "HOST"))
                return true;

        return false;

}

static inline bool match_ftp_control(lpi_data_t *data, 
		lpi_module_t *mod UNUSED) {

	/* Rule out SMTP which uses similar reply codes and commands */
	if (data->server_port == 25 || data->client_port == 25)
                return false;

        if (match_ftp_reply_code(data->payload[0], data->payload_len[0])) {
                if (match_ftp_command(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_ftp_reply_code(data->payload[1], data->payload_len[1])) {
                if (match_ftp_command(data->payload[0], data->payload_len[0]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_ftpcontrol = {
	LPI_PROTO_FTP_CONTROL,
	LPI_CATEGORY_FILES,
	"FTP_Control",
	3,
	match_ftp_control
};

void register_ftpcontrol(LPIModuleMap *mod_map) {
	register_protocol(&lpi_ftpcontrol, mod_map);
}

