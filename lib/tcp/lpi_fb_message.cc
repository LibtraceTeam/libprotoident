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

/* Observed while using Facebook Messenger -- I used the unofficial desktop
 * version (https://messengerfordesktop.com/) to talk to another account
 * logged into a web browser. I suspect direct app->app voice/video calls
 * may use the protocol more heavily.
 */

static inline bool match_fb_msg_104(uint32_t payload, uint32_t len) {
        if (len != 104)
                return false;
        if (MATCH(payload, 0x01, 0x13, 0x00, 0x54))
                return true;
        return false;
}

static inline bool match_fb_msg_28(uint32_t payload, uint32_t len) {
        if (len != 28)
                return false;
        if (MATCH(payload, 0x00, 0x03, 0x00, 0x08))
                return true;
        return false;
}

static inline bool match_fb_message(lpi_data_t *data, lpi_module_t *mod UNUSED) {

        if (data->server_port != 3478 && data->client_port != 3478 &&
                        data->server_port != 443 && data->client_port != 443)
                return false;

        if (match_fb_msg_28(data->payload[0], data->payload_len[0])) {
                if (match_fb_msg_104(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_fb_msg_28(data->payload[1], data->payload_len[1])) {
                if (match_fb_msg_104(data->payload[0], data->payload_len[0]))
                        return true;
        }


	return false;
}

static lpi_module_t lpi_fb_message = {
	LPI_PROTO_FACEBOOK_MESSENGER,
	LPI_CATEGORY_CHAT,
	"FacebookMessenger",
	9,
	match_fb_message
};

void register_fb_message(LPIModuleMap *mod_map) {
	register_protocol(&lpi_fb_message, mod_map);
}

