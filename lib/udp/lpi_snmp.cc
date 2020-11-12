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

static inline bool match_snmp_payload(uint32_t payload, uint32_t len) {

        /* SNMP is BER encoded, which is an ass to decode */
        uint8_t snmplen = 0;
        uint8_t *byte;

	if (len == 0)
		return true;

        /* Must be a SEQUENCE */
        if (!MATCH(payload, 0x30, ANY, ANY, ANY))
                return false;

        byte = ((uint8_t *)&payload) + 1;

        if (*byte< 0x80) {
                snmplen = *byte;

                if (!MATCH(payload, 0x30, ANY, 0x02, 0x01))
                        return false;
                if (len - 2 != snmplen)
                        return false;
                return true;
        }

        if (*byte == 0x81) {
                snmplen = *(byte + 1);

                if (!MATCH(payload, 0x30, 0x81, ANY, 0x02))
                        return false;
                if (len - 3 != snmplen)
                        return false;
                return true;
        }

        if (*byte == 0x82) {
                uint16_t longlen = *((uint16_t *)(byte + 1));

                if (len - 4 != ntohs(longlen))
                        return false;
                return true;
        }

        return false;

}


static inline bool match_snmp(lpi_data_t *data, lpi_module_t *mod UNUSED) {

	if (!match_snmp_payload(data->payload[0], data->payload_len[0]))
                return false;
        if (!match_snmp_payload(data->payload[1], data->payload_len[1]))
                return false;

        return true;


}

static lpi_module_t lpi_snmp = {
	LPI_PROTO_UDP_SNMP,
	LPI_CATEGORY_MONITORING,
	"SNMP",
	3,
	match_snmp
};

void register_snmp(LPIModuleMap *mod_map) {
	register_protocol(&lpi_snmp, mod_map);
}

