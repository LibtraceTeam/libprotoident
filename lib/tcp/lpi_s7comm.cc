/*
 *
 * Copyright (c) 2011-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libprotoident.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

static inline bool match_s7comm_sizes(lpi_data_t *data) {

    /* Based on observations, size of first package is equal
     * in both directions.
     */

    if (data->payload_len[0] == data->payload_len[1]) {
        return true;
    }
    return false;
}

static inline bool match_s7comm_port(lpi_data_t *data) {
     
    if (data->server_port == 102 || data->client_port == 102) {
        return true;
    }
    return false;
}

static bool match_s7comm(lpi_data_t *data, lpi_module_t *mod UNUSED) {

    /* S7COMM uses port 102 */
    if (!match_s7comm_port(data))
        return false;

    /* S7COMM is transported via TPKT */
    if (!match_tpkt(data->payload[0], data->payload_len[0]))
        return false;
    if (!match_tpkt(data->payload[1], data->payload_len[1]))
        return false;   
    
    if (match_s7comm_sizes(data))
        return true;
    
    return false;
}

static lpi_module_t lpi_s7comm = {
    LPI_PROTO_S7COMM,
    LPI_CATEGORY_ICS,
    "S7COMM",
    7, /*  Must come before TPKT */
    match_s7comm
};

void register_s7comm(LPIModuleMap *mod_map) {
    register_protocol(&lpi_s7comm, mod_map);
}
