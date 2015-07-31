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
 * $Id: lpi_yahoo_games.cc 60 2011-02-02 04:07:52Z salcock $
 */

#include <string.h>

#include "libprotoident.h"
#include "proto_manager.h"
#include "proto_common.h"

/* This traffic all seems to go to games.X.yahoo.com, so I'm going to assume
 * that this is Yahoo Games */

static inline bool match_yahoo_games_req(uint32_t payload, uint32_t len) {

        if (len != 1)
                return false;
        if (!MATCH(payload, 0x00, 0x00, 0x00, 0x00))
                return false;
        return true;

}

static inline bool match_yahoo_games_resp(uint32_t payload, uint32_t len) {

        if (len != 22)
                return false;
        if (!MATCH(payload, 0x81, 0xd3, 0x70, 0x6c))
                return false;
        return true;

}

static inline bool match_yahoo_games(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_yahoo_games_req(data->payload[0], data->payload_len[0])) {
                if (match_yahoo_games_resp(data->payload[1], data->payload_len[1])) {
                        return true;
                }
        }
        if (match_yahoo_games_req(data->payload[1], data->payload_len[1])) {
                if (match_yahoo_games_resp(data->payload[0], data->payload_len[0])) {
                        return true;
                }
        }

	return false;
}

static lpi_module_t lpi_yahoo_games = {
	LPI_PROTO_YAHOO_GAMES,
	LPI_CATEGORY_GAMING,
	"YahooGames",
	4,
	match_yahoo_games
};

void register_yahoo_games(LPIModuleMap *mod_map) {
	register_protocol(&lpi_yahoo_games, mod_map);
}

