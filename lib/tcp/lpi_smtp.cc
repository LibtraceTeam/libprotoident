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

static inline bool match_smtp_command(uint32_t payload, uint32_t len) {

        if (MATCHSTR(payload, "EHLO"))
                return true;
        if (MATCHSTR(payload, "ehlo"))
                return true;
        if (MATCHSTR(payload, "HELO"))
                return true;
        if (MATCHSTR(payload, "helo"))
                return true;
        if (MATCHSTR(payload, "NOOP"))
                return true;
        if (MATCHSTR(payload, "XXXX"))
                return true;
        if (MATCHSTR(payload, "HELP"))
                return true;
        if (MATCHSTR(payload, "EXPN"))
                return true;

        /* Turns out there are idiots who send their ehlos one byte at a 
         * time :/ */
        if (MATCH(payload, 'e', 0x00, 0x00, 0x00) && len == 1)
                return true;
        if (MATCH(payload, 'E', 0x00, 0x00, 0x00) && len == 1)
                return true;
        if (MATCH(payload, 'h', 0x00, 0x00, 0x00) && len == 1)
                return true;
        if (MATCH(payload, 'H', 0x00, 0x00, 0x00) && len == 1)
                return true;

        return false;

}

static inline bool match_smtp_banner(uint32_t payload, uint32_t len) {

        /* Stupid servers that only send the banner one or two bytes at
         * a time! */

        if (len == 1) {
                if (MATCH(payload, '2', 0x00, 0x00, 0x00))
                        return true;
                return false;
        }
        if (len == 2) {
                if (MATCH(payload, '2', '2', 0x00, 0x00))
                        return true;
                return false;
        }
        if (len == 3) {
                if (MATCH(payload, '2', '2', '0', 0x00))
                        return true;
                return false;
        }

        if (MATCH(payload, '2', '2', '0', ' '))
                return true;

        if (MATCH(payload, '2', '2', '0', '-'))
                return true;

        return false;
}


static inline bool match_smtp(lpi_data_t *data, lpi_module_t *mod UNUSED) {


        /* Match all the random error codes */
        if (data->payload_len[0] == 0 || data->payload_len[1] == 0) {
                if (match_str_either(data, "220 "))
                        return true;
                if (match_str_either(data, "450 "))
                        return true;
                if (match_str_either(data, "550 "))
                        return true;
                if (match_str_either(data, "550-"))
                        return true;
                if (match_str_either(data, "421 "))
                        return true;
                if (match_str_either(data, "421-"))
                        return true;
                if (match_str_either(data, "451 "))
                        return true;
                if (match_str_either(data, "451-"))
                        return true;
                if (match_str_either(data, "452 "))
                        return true;
                if (match_str_either(data, "420 "))
                        return true;
                if (match_str_either(data, "571 "))
                        return true;
                if (match_str_either(data, "553 "))
                        return true;
                if (match_str_either(data, "554 "))
                        return true;
                if (match_str_either(data, "554-"))
                        return true;
                if (match_str_either(data, "476 "))
                        return true;
                if (match_str_either(data, "475 "))
                        return true;
        }

        if (match_str_either(data, "QUIT") && (data->server_port == 25 ||
                        data->client_port == 25))
                return true;
        if (match_str_either(data, "quit") && (data->server_port == 25 ||
                        data->client_port == 25))
                return true;
        /* Match the server banner code */

        if (match_smtp_banner(data->payload[0], data->payload_len[0])) {
                if (match_smtp_command(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_smtp_banner(data->payload[1], data->payload_len[1])) {
                if (match_smtp_command(data->payload[0], data->payload_len[0]))
                        return true;
        }

        return false;
}

static lpi_module_t lpi_smtp = {
	LPI_PROTO_SMTP,
	LPI_CATEGORY_MAIL,
	"SMTP",
	2,
	match_smtp
};

void register_smtp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_smtp, mod_map);
}

