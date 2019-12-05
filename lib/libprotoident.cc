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

#define __STDC_FORMAT_MACROS
#define __STDC_LIMIT_MACROS

#include <stdio.h>
#include <assert.h>
#include <libtrace.h>
#include <inttypes.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>

#include "libprotoident.h"
#include "proto_manager.h"


bool init_called = false;
LPIModuleMap TCP_protocols;
LPIModuleMap UDP_protocols;

lpi_module_t *lpi_icmp = NULL;
lpi_module_t *lpi_unsupported = NULL;
lpi_module_t *lpi_unknown_tcp = NULL;
lpi_module_t *lpi_unknown_udp = NULL;

static LPINameMap lpi_names;
static LPIProtocolMap lpi_protocols;
static LPICategoryMap lpi_categories;
static LPICategoryProtocolMap lpi_category_protocols;

static int seq_cmp (uint32_t seq_a, uint32_t seq_b) {

        if (seq_a == seq_b) return 0;


        if (seq_a > seq_b)
                return (int)(seq_a - seq_b);
        else
                /* WRAPPING */
                return (int)(UINT32_MAX - ((seq_b - seq_a) - 1));

}


int lpi_init_library() {

	if (init_called) {
		fprintf(stderr, "WARNING: lpi_init_library has already been called\n");
		return 0;
	}
	
	if (register_tcp_protocols(&TCP_protocols) == -1) 
		return -1;
	
	if (register_udp_protocols(&UDP_protocols) == -1) 
		return -1;

	init_other_protocols(&lpi_names, &lpi_protocols, &lpi_category_protocols);

	register_names(&TCP_protocols, &lpi_names, &lpi_protocols, &lpi_category_protocols);
	register_names(&UDP_protocols, &lpi_names, &lpi_protocols, &lpi_category_protocols);

	register_category_names(&lpi_categories);

	init_called = true;

	if (TCP_protocols.empty() && UDP_protocols.empty()) {
		fprintf(stderr, "WARNING: No protocol modules loaded\n");
		return -1;
	}


	return 0;

}

void lpi_free_library() {

	free_protocols(&TCP_protocols);
	free_protocols(&UDP_protocols);

   if (lpi_icmp != NULL) {
      delete lpi_icmp;
      lpi_icmp = NULL;
   }

   if (lpi_unsupported != NULL) {
      delete lpi_unsupported;
      lpi_unsupported = NULL;
   }

   if (lpi_unknown_tcp != NULL) {
      delete lpi_unknown_tcp;
      lpi_unknown_tcp = NULL;
   }

   if (lpi_unknown_udp != NULL) {
      delete lpi_unknown_udp;
      lpi_unknown_udp = NULL;
   }

	init_called = false;
}

void lpi_init_data(lpi_data_t *data) {

	data->payload[0] = 0;
	data->payload[1] = 0;
	data->seen_syn[0] = false;
	data->seen_syn[1] = false;
	data->seqno[0] = 0;
	data->seqno[1] = 0;
	data->observed[0] = 0;
	data->observed[1] = 0;
	data->server_port = 0;
	data->client_port = 0;
	data->trans_proto = 0;
	data->payload_len[0] = 0;
	data->payload_len[1] = 0;
	data->ips[0] = 0;
	data->ips[1] = 0;

}

static int update_tcp_flow(lpi_data_t *data, libtrace_tcp_t *tcp, uint8_t dir,
		uint32_t rem, uint32_t psize) {
	uint32_t seq = 0;

	if (rem < sizeof(libtrace_tcp_t))
		return 0;
	if (tcp->rst)
		return 0;
	
	if (data->server_port == 0) {
		data->server_port = ntohs(tcp->dest);
		data->client_port = ntohs(tcp->source);
	}

	seq = ntohl(tcp->seq);

	if (tcp->syn && data->payload_len[dir] == 0) {
		data->seqno[dir] = seq + 1;
		data->seen_syn[dir] = true;
	}

	/* Ok, we've got some payload but we never saw the SYN for this
	 * direction. What do we do?
	 *
	 * Current idea: just assume this is the first payload bearing
	 * packet. Better than running around with an uninitialised seqno */
	if (data->seen_syn[dir] == false && psize > 0) {
		data->seqno[dir] = seq;
		data->seen_syn[dir] = true;
	}

	if (seq_cmp(seq, data->seqno[dir]) != 0)
		return 0;
	//data->seqno[dir] = seq;

	return 1;
}

static int update_udp_flow(lpi_data_t *data, libtrace_udp_t *udp,
		uint32_t rem) {

	if (rem < sizeof(libtrace_udp_t))
		return 0;
	
	if (data->server_port == 0) {
		data->server_port = ntohs(udp->dest);
		data->client_port = ntohs(udp->source);
	}

	return 1;
}

int lpi_update_data(libtrace_packet_t *packet, lpi_data_t *data, uint8_t dir) {

	char *payload = NULL;
	uint32_t psize = 0;
	uint32_t rem = 0;
	uint8_t proto = 0;
	void *transport;
	uint32_t four_bytes;
	libtrace_ip_t *ip = NULL;

	//tcp = trace_get_tcp(packet);
	psize = trace_get_payload_length(packet);

	/* Don't bother if we've observed 32k of data - the first packet must
	 * surely been within that. This helps us avoid issues with sequence
	 * number wrapping when doing the reordering check below */
	if (data->observed[dir] > 32 * 1024)
		return 0;
	
	data->observed[dir] += psize;
	
	/* If we're TCP, we have to wait to check that we haven't been
	 * reordered */
	if (data->trans_proto != 6 && data->payload_len[dir] != 0)
		return 0;
	
	transport = trace_get_transport(packet, &proto, &rem);
	if (data->trans_proto == 0)
		data->trans_proto = proto;
	
	if (transport == NULL || rem == 0)
		return 0;		

	if (proto == 6) {
		if (update_tcp_flow(data, (libtrace_tcp_t *)transport, dir, rem, psize) == 0) 
			return 0;
		payload = (char *)trace_get_payload_from_tcp(
				(libtrace_tcp_t *)transport, &rem);
	} 

	if (proto == 17) {
		if (update_udp_flow(data, (libtrace_udp_t *)transport, rem) == 0)
			return 0;
		payload = (char *)trace_get_payload_from_udp(
				(libtrace_udp_t *)transport, &rem);
	}

	ip = trace_get_ip(packet);
	
	if (payload == NULL)
		return 0;
	if (psize <= 0)
		return 0;

	four_bytes = (*(uint32_t *)payload);
	
	if (psize < 4) {
		four_bytes = (ntohl(four_bytes)) >> (8 * (4 - psize));		
		four_bytes = htonl(four_bytes << (8 * (4 - psize)));		
	}

	data->payload[dir] = four_bytes;
	data->payload_len[dir] = psize;

	if (ip != NULL && data->ips[0] == 0) {
		if (dir == 0) {
			data->ips[0] = ip->ip_src.s_addr;
			data->ips[1] = ip->ip_dst.s_addr;
		} else {
			data->ips[1] = ip->ip_src.s_addr;
			data->ips[0] = ip->ip_dst.s_addr;
		}
	}

	return 1;

}

static lpi_module_t *test_protocol_list(LPIModuleList *ml, lpi_data_t *data) {

	LPIModuleList::iterator l_it;
	
	/* Turns out naively looping through the modules is quicker
	 * than trying to do intelligent stuff with threads. Most
	 * callbacks complete very quickly so threading overhead is a
	 * major problem */
	for (l_it = ml->begin(); l_it != ml->end(); l_it ++) {
		lpi_module_t *module = *l_it;

		/* To save time, I'm going to break on the first successful
		 * match. A threaded version would wait for all the modules
		 * to run, storing all successful results in a list of some
		 * sort and selecting an appropriate result from there.
		 */

		if (module->lpi_callback(data, module)) 
			return module;
		
	}

	return NULL;
}
static lpi_module_t *guess_protocol(LPIModuleMap *modmap, lpi_data_t *data) {

	lpi_module_t *proto = NULL;

	LPIModuleMap::iterator m_it;

	/* Deal with each priority in turn - want to match higher priority
	 * rules first. 
	 */

	for (m_it = modmap->begin(); m_it != modmap->end(); m_it ++) {
		LPIModuleList *ml = m_it->second;
		
		proto = test_protocol_list(ml, data);

		if (proto != NULL)
			break;
	}

	return proto;

}

lpi_module_t *lpi_guess_protocol(lpi_data_t *data) {

	lpi_module_t *p = NULL;

	if (!init_called) {
		fprintf(stderr, "lpi_init_library was never called - cannot guess the protocol\n");
		return NULL;
	}

	switch(data->trans_proto) {
		case TRACE_IPPROTO_ICMP:
			return lpi_icmp;
		case TRACE_IPPROTO_TCP:
			p = guess_protocol(&TCP_protocols, data);
			if (p == NULL)
				p = lpi_unknown_tcp;
			return p;

		case TRACE_IPPROTO_UDP:
			p = guess_protocol(&UDP_protocols, data);
			if (p == NULL)
				p = lpi_unknown_udp;
			return p;
		default:
			return lpi_unsupported;
	}


	return p;
}
	
lpi_category_t lpi_categorise(lpi_module_t *module) {

	if (module == NULL)
		return LPI_CATEGORY_NO_CATEGORY;

	return module->category;

}

const char *lpi_print_category(lpi_category_t category) {

	switch(category) {
		case LPI_CATEGORY_WEB:
			return "Web";
		case LPI_CATEGORY_MAIL:
			return "Mail";
		case LPI_CATEGORY_CHAT:
			return "Chat";
		case LPI_CATEGORY_P2P:
			return "P2P";
		case LPI_CATEGORY_P2P_STRUCTURE:
			return "P2P_Structure";
		case LPI_CATEGORY_KEY_EXCHANGE:
			return "Key_Exchange";
		case LPI_CATEGORY_ECOMMERCE:
			return "ECommerce";
		case LPI_CATEGORY_GAMING:
			return "Gaming";
		case LPI_CATEGORY_ENCRYPT:
			return "Encryption";
		case LPI_CATEGORY_MONITORING:
			return "Measurement";
		case LPI_CATEGORY_NEWS:
			return "News";
		case LPI_CATEGORY_MALWARE:
			return "Malware";
		case LPI_CATEGORY_SECURITY:
			return "Security";
		case LPI_CATEGORY_ANTISPAM:
			return "Antispam";
		case LPI_CATEGORY_VOIP:
			return "VOIP";
		case LPI_CATEGORY_TUNNELLING:
			return "Tunnelling";
		case LPI_CATEGORY_NAT:
			return "NAT_Traversal";
		case LPI_CATEGORY_STREAMING:
			return "Streaming";
		case LPI_CATEGORY_SERVICES:
			return "Services";
		case LPI_CATEGORY_DATABASES:
			return "Databases";
		case LPI_CATEGORY_FILES:
			return "File_Transfer";
		case LPI_CATEGORY_REMOTE:
			return "Remote_Access";
		case LPI_CATEGORY_TELCO:
			return "Telco_Services";
		case LPI_CATEGORY_P2PTV:
			return "P2PTV";
		case LPI_CATEGORY_RCS:
			return "Revision_Control";
		case LPI_CATEGORY_LOGGING:
			return "Logging";
		case LPI_CATEGORY_PRINTING:
			return "Printing";
		case LPI_CATEGORY_TRANSLATION:
			return "Translation";
		case LPI_CATEGORY_CDN:
			return "CDN";
		case LPI_CATEGORY_CLOUD:
			return "Cloud";
		case LPI_CATEGORY_NOTIFICATION:
			return "Notification";
		case LPI_CATEGORY_SERIALISATION:
			return "Serialisation";
		case LPI_CATEGORY_BROADCAST:
			return "Broadcast";
		case LPI_CATEGORY_LOCATION:
			return "Location";
		case LPI_CATEGORY_CACHING:
			return "Caching";
		case LPI_CATEGORY_ICS:
			return "ICS";
		case LPI_CATEGORY_MOBILE_APP:
			return "Mobile App";
		case LPI_CATEGORY_IPCAMERAS:
			return "IP Cameras";
		case LPI_CATEGORY_EDUCATIONAL:
			return "Educational";
                case LPI_CATEGORY_MESSAGE_QUEUE:
                        return "Message_Queuing";
		case LPI_CATEGORY_ICMP:
			return "ICMP";
		case LPI_CATEGORY_MIXED:
			return "Mixed";
		case LPI_CATEGORY_NOPAYLOAD:
			return "No_Payload";
		case LPI_CATEGORY_UNKNOWN:
			return "Unknown";
		case LPI_CATEGORY_UNSUPPORTED:
			return "Unsupported";
		case LPI_CATEGORY_NO_CATEGORY:
			return "Uncategorised";
		case LPI_CATEGORY_LAST:
			return "Invalid_Category";
	}

	return "Invalid_Category";

}
			
const char *lpi_print(lpi_protocol_t proto) {

	LPINameMap::iterator it;

	it = lpi_names.find(proto);

	if (it == lpi_names.end()) {
		return "NULL";
	}	
	return (it->second);
	
}

lpi_protocol_t lpi_get_protocol_by_name(char *name) {

	LPIProtocolMap::iterator it;

	it = lpi_protocols.find(name);

	if (it == lpi_protocols.end()) {
		return LPI_PROTO_UNKNOWN;
	}

	return (it->second);
}

lpi_category_t lpi_get_category_by_name(char *name) {

	LPICategoryMap::iterator it;

	it = lpi_categories.find(name);

	if (it == lpi_categories.end()) {
		return LPI_CATEGORY_UNKNOWN;
	}

	return (it->second);
}

lpi_category_t lpi_get_category_by_protocol(lpi_protocol_t protocol) {

	LPICategoryProtocolMap::iterator it;

	it = lpi_category_protocols.find(protocol);

	if (it == lpi_category_protocols.end()) {
		return LPI_CATEGORY_UNKNOWN;
	}

	return (it->second);
}

bool lpi_is_protocol_inactive(lpi_protocol_t proto) {

	LPINameMap::iterator it;

	it = lpi_names.find(proto);

	if (it == lpi_names.end()) {
		return true;
	}	
	return false;

}

