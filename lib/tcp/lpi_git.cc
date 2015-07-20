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
 * $Id: lpi_git.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>
#include <stdlib.h>
#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_git_header(uint32_t payload, uint32_t len) {
        int i;
        char headerstr[4];
        uint8_t *pl = (uint8_t *)(&payload);

        if (len == 0)
                return true;

        for (i = 0; i < 4; i++) {
                headerstr[i] = (char)(*pl);
                pl++;
        }

        uint32_t replen = strtoul(headerstr, NULL, 16);

        if (replen != len)
                return false;

        return true;
}

static inline bool match_git(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_git_header(data->payload[0], data->payload_len[0])) {
                if (match_git_header(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_git_header(data->payload[1], data->payload_len[1])) {
                if (match_git_header(data->payload[0], data->payload_len[0]))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_git = {
	LPI_PROTO_GIT,
	LPI_CATEGORY_RCS,
	"Git",
	5,
	match_git
};

void register_git(LPIModuleMap *mod_map) {
	register_protocol(&lpi_git, mod_map);
}

