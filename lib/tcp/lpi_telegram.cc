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

#include <stdio.h>
/* Protocol is documented at https://core.telegram.org/mtproto */


static inline bool match_abridged_telegram_query(uint32_t payload, uint32_t len) {

        if (MATCH(payload, 0xef, ANY, ANY, ANY)) {
        
                /* Bottom 7 bits of byte 2 are a length field */
                uint32_t lenfield = ((ntohl(payload) >> 16) & 0x7f);

                if (len - 2 == lenfield * 4) {
                        return true;
                }

                /* XXX Some clients appear to follow the query with some
                 * other message which TCP will combine into the same
                 * segment, so we can still fail the length check. Do
                 * we want to consider removing the length check and just
                 * rely on the 0x3f byte for matching this?
                 */

        }

        /* All 1s in the length field means the next three bytes are a
         * length field. In this case, the first packet will almost
         * certainly be MSS sized.
         */
        if (MATCH(payload, 0xef, 0x7f, ANY, ANY)) {
                if (len >= 1300)
                        return true;
        }

        return false;
}

static inline bool match_telegram_query(uint32_t payload, uint32_t len) {

        /* Random bytes but always 105 based on my observations */

        if (len == 105)
                return true;

        return false;
}

static inline bool match_abridged_telegram_resp(uint32_t payload, uint32_t len) {

        /* Fast acknowledgement -- technically this should only match if
         * top bit of the length field is set, but we're probably ok to not
         * enforce that.
         */
        if (len == 4 && (payload & 0x00000080))
                return true;

        /* Look out for very large packets that won't fit in a single segment */
        if (MATCH(payload, 0x7f, ANY, ANY, 0x00))
                return true;

        /* Otherwise, first byte is the length field */
        uint32_t lenfield = ((ntohl(payload) >> 24));
        
        if (lenfield * 4 == len - 1)
                return true;
        return false;

}

static inline bool match_telegram_resp(uint32_t payload, uint32_t len) {

        /* First four bytes are a length field */
        uint32_t lenfield = ntohl(payload);
        
        if (lenfield * 4 == len - 1)
                return true;
        return false;

}


static inline bool match_telegram(lpi_data_t *data, lpi_module_t *mod UNUSED) {


        if (match_abridged_telegram_query(data->payload[0], data->payload_len[0])) {
                if (match_abridged_telegram_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_abridged_telegram_query(data->payload[1], data->payload_len[1])) {
                if (match_abridged_telegram_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (match_telegram_query(data->payload[0], data->payload_len[0])) {
                if (match_telegram_resp(data->payload[1], data->payload_len[1]))
                        return true;
        }

        if (match_telegram_query(data->payload[1], data->payload_len[1])) {
                if (match_telegram_resp(data->payload[0], data->payload_len[0]))
                        return true;
        }

        if (data->payload_len[0] == 96 && data->payload_len[1] == 52) {
                if (MATCH(data->payload[0], 0x60, 0x00, 0x00, 0x00) && 
                                MATCH(data->payload[1], 0x34, 0x00, 0x00, 0x00))
                        return true;
        }

        if (data->payload_len[1] == 96 && data->payload_len[0] == 52) {
                if (MATCH(data->payload[1], 0x60, 0x00, 0x00, 0x00) && 
                                MATCH(data->payload[0], 0x34, 0x00, 0x00, 0x00))
                        return true;
        }

	return false;
}

static lpi_module_t lpi_telegram = {
	LPI_PROTO_TELEGRAM,
	LPI_CATEGORY_CHAT,
	"TelegramMessenger",
	10,
	match_telegram
};

void register_telegram(LPIModuleMap *mod_map) {
	register_protocol(&lpi_telegram, mod_map);
}

