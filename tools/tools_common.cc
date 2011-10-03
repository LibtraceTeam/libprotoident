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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tools_common.h"

int convert_mac_string(char *string, uint8_t *bytes) {

        uint32_t digits[6];

        if (sscanf(string, "%x:%x:%x:%x:%x:%x", &(digits[0]),
                        &(digits[1]), &(digits[2]), &(digits[3]),
                        &(digits[4]), &(digits[5])) != 6)
                return -1;

        for (int i = 0; i < 6; i++) {

                if (digits[i] > 255)
                        return -1;
                bytes[i] = (uint8_t)digits[i];
        }

        return 0;

}

int mac_get_direction(libtrace_packet_t *packet, uint8_t *mac_bytes) {

	uint8_t *src_mac = NULL;
        uint8_t *dest_mac = NULL;

	src_mac = trace_get_source_mac(packet);
        dest_mac = trace_get_destination_mac(packet);

        if (!src_mac || !dest_mac) {
                return -1;
        }
	
	if (memcmp(src_mac, mac_bytes, 6) == 0)
                return 0;
        else if (memcmp(dest_mac, mac_bytes, 6) == 0)
                return 1;

	return -1;

}

int port_get_direction(libtrace_packet_t *packet) {
	uint16_t src_port;
        uint16_t dst_port;
	int dir = 2;
	void *l3;
	uint16_t ethertype;
	uint32_t rem;
	libtrace_ip_t *ip = NULL;
	libtrace_ip6_t *ip6 = NULL;
	uint8_t proto;

	src_port = trace_get_source_port(packet);
        dst_port = trace_get_destination_port(packet);

	l3 = trace_get_layer3(packet, &ethertype, &rem);
		
	if (ethertype == TRACE_ETHERTYPE_IP && rem >= sizeof(libtrace_ip_t)) {
		ip = (libtrace_ip_t *)l3;
		proto = ip->ip_p;
	}
	if (ethertype == TRACE_ETHERTYPE_IPV6 && rem >= sizeof(libtrace_ip6_t)) 	{
		ip6 = (libtrace_ip6_t *)l3;
		proto = ip6->nxt;
	}


        if (src_port == dst_port) {

		if (l3 == NULL || rem == 0)
			return dir;

		if (ip) {
	                if (ip->ip_src.s_addr < ip->ip_dst.s_addr)
        	                dir = 0;
        	        else
        	                dir = 1;
		}

		if (ip6) {
			if (memcmp(&(ip6->ip_src), &(ip6->ip_dst), 
						sizeof(struct in6_addr)) < 0) {
				dir = 0;
			} else {
				dir = 1;
			}
		}

        } else {
                if (trace_get_server_port(proto, src_port, dst_port) 
					== USE_SOURCE) {
                        dir = 0;
		} else {
                        dir = 1;
		}
        }

	return dir;
}
