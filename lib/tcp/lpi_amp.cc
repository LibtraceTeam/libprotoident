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
 * $Id: lpi_amp.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_amp_throughput(lpi_data_t *data) {
        /* AMP Throughput generally uses port 8826 */
        if (data->server_port != 8826 && data->client_port != 8826)
                return false;

        /* AMP Throughput tests are large one-way data transfers */
        if (data->payload_len[0] != 0 && data->payload_len[1] != 0)
                return false;

        /* Packets are always going to be MSS-sized -- assume MTU is no
         * smaller than 1280 bytes */
        if (data->payload_len[0] < 1240 && data->payload_len[1] < 1240)
                return false;

        return true;

}

static inline bool match_amp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_amp_throughput(data))
                return true;

	return false;
}

static lpi_module_t lpi_amp = {
	LPI_PROTO_AMP,
	LPI_CATEGORY_MONITORING,
	"AMP",
	240,    /* AMP is not something I'd expect to see outside of Waikato */
	match_amp
};

void register_amp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_amp, mod_map);
}

