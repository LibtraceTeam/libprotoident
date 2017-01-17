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

/* Twitch IRC expects the use of a CAP command to check for membership lists.
 * The response will begin with :tmi.twitch.tv, regardless of what the
 * result of the CAP command is.
 */

static inline bool match_twitch_cap(uint32_t payload) {
        if (MATCH(payload, 'C', 'A', 'P', 0x20))
                return true;
        return false;
}

static inline bool match_twitch_tmi(uint32_t payload) {
        if (MATCH(payload, ':', 't', 'm', 'i'))
                return true;
        return false;
}


static inline bool match_twitch_irc(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (match_twitch_cap(data->payload[1])) {
                if (match_twitch_tmi(data->payload[0])) {
                        return true;
                }
        }

        if (match_twitch_cap(data->payload[0])) {
                if (match_twitch_tmi(data->payload[1])) {
                        return true;
                }
        }

	return false;
}

static lpi_module_t lpi_twitch_irc = {
	LPI_PROTO_TWITCH_IRC,
	LPI_CATEGORY_CHAT,
	"TwitchIRC",
	5,
	match_twitch_irc
};

void register_twitch_irc(LPIModuleMap *mod_map) {
	register_protocol(&lpi_twitch_irc, mod_map);
}

