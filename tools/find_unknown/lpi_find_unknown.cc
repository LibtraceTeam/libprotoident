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


#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <inttypes.h>
#include <signal.h>

#include <libtrace.h>
#include <libflowmanager.h>
#include <libprotoident.h>

#include "../tools_common.h"

enum {
	DIR_METHOD_TRACE,
	DIR_METHOD_MAC,
	DIR_METHOD_PORT
};

int dir_method = DIR_METHOD_PORT;

bool only_dir0 = false;
bool only_dir1 = false;

bool require_both = false;
bool nat_hole = false;

static volatile int done = 0;

char *local_mac = NULL;
uint8_t mac_bytes[6];

/* This data structure is used to demonstrate how to use the 'extension' 
 * pointer to store custom data for a flow */
typedef struct unknown {
	uint8_t init_dir;
	uint64_t in_bytes;
	uint64_t out_bytes;
	uint64_t in_pkts;
	uint64_t out_pkts;
	double start_ts;
	lpi_data_t lpi;
} UnknownFlow;

/* Initialises the custom data for the given flow. Allocates memory for a
 * UnknownFlow structure and ensures that the extension pointer points at
 * it.
 */
void init_unknown_flow(Flow *f, uint8_t dir, double ts) {
	UnknownFlow *unk = NULL;

	unk = (UnknownFlow *)malloc(sizeof(UnknownFlow));
	unk->init_dir = dir;
	unk->in_bytes = 0;
	unk->out_bytes = 0;
	unk->in_pkts = 0;
	unk->out_pkts = 0;
	unk->start_ts = ts;
	lpi_init_data(&unk->lpi);
	f->extension = unk;
}

void dump_payload(lpi_data_t lpi, uint8_t dir) {

	int i;
	uint8_t *pl = (uint8_t *)(&(lpi.payload[dir]));
	uint32_t len = lpi.payload_len[dir];


	printf("%08x ", ntohl(lpi.payload[dir]));
	
	for (i = 0; i < 4; i++) {
		
		if (*pl > 32 && *pl < 126) {
			printf("%c", *pl);
		} else {
			printf(".");
		}
		pl ++;
	}

	printf(" %u", lpi.payload_len[dir]);
	
	printf(" ");

}

void display_unknown(Flow *f, UnknownFlow *unk) {

        char s_ip[500];
	char c_ip[500];
        char str[1000];


	if (only_dir0 && unk->init_dir == 1)
		return;
	if (only_dir1 && unk->init_dir == 0)
		return;
	if (require_both) {
		if (unk->lpi.payload_len[0] == 0 || 
				unk->lpi.payload_len[1] == 0) {
			return;
		}
	}

	if (nat_hole) {
                if (unk->init_dir != 1)
                        return;
                if (unk->lpi.payload_len[0] == 0 && unk->in_pkts <= 3)
                        return;
        }

	f->id.get_server_ip_str(s_ip);
	f->id.get_client_ip_str(c_ip);
	
        snprintf(str, 1000, "%s %s %u %u %u %.3f %" PRIu64 " %" PRIu64,  
			s_ip, c_ip,
                        f->id.get_server_port(), f->id.get_client_port(),
                        f->id.get_protocol(), unk->start_ts,
			unk->out_bytes, unk->in_bytes);

	printf("%s ", str);

	dump_payload(unk->lpi, 0);
	dump_payload(unk->lpi, 1);
	printf("\n");


}

/* Expires all flows that libflowmanager believes have been idle for too
 * long. The exp_flag variable tells libflowmanager whether it should force
 * expiry of all flows (e.g. if you have reached the end of the program and
 * want the stats for all the still-active flows). Otherwise, only flows
 * that have been idle for longer than their expiry timeout will be expired.
 */
void expire_unknown_flows(double ts, bool exp_flag) {
        Flow *expired;
	lpi_module_t *proto;

        /* Loop until libflowmanager has no more expired flows available */
	while ((expired = lfm_expire_next_flow(ts, exp_flag)) != NULL) {

                UnknownFlow *unk = (UnknownFlow *)expired->extension;
		
		proto = lpi_guess_protocol(&unk->lpi);
	
		if (proto->protocol == LPI_PROTO_UNKNOWN || 
				proto->protocol == LPI_PROTO_UDP) {
			display_unknown(expired, unk);
		}

		/* Don't forget to free our custom data structure */
                free(unk);

		/* VERY IMPORTANT: delete the Flow structure itself, even
		 * though we did not directly allocate the memory ourselves */
                delete(expired);
        }
}


void per_packet(libtrace_packet_t *packet) {

        Flow *f;
        UnknownFlow *unk = NULL;
        uint8_t dir;
        bool is_new = false;

        libtrace_tcp_t *tcp = NULL;
        double ts;

	void *l3;
        uint16_t l3_type;

        /* Libflowmanager only deals with IP traffic, so ignore anything
	 * that does not have an IP header */
        l3 = trace_get_layer3(packet, &l3_type, NULL);
        if (l3_type != TRACE_ETHERTYPE_IP && l3_type != TRACE_ETHERTYPE_IPV6) 
		return;
        if (l3 == NULL) return;

	/* Expire all suitably idle flows */
        ts = trace_get_seconds(packet);
        expire_unknown_flows(ts, false);

	/* Determine packet direction */
	if (dir_method == DIR_METHOD_TRACE) {
		dir = trace_get_direction(packet);
	}
	if (dir_method == DIR_METHOD_MAC) {
		dir = mac_get_direction(packet, mac_bytes);
	}
	if (dir_method == DIR_METHOD_PORT) {
		dir = port_get_direction(packet);
	}


	if (dir != 0 && dir != 1)
		return;

        /* Match the packet to a Flow - this will create a new flow if
	 * there is no matching flow already in the Flow map and set the
	 * is_new flag to true. */
        f = lfm_match_packet_to_flow(packet, dir, &is_new);

	/* Libflowmanager did not like something about that packet - best to
	 * just ignore it and carry on */
        if (f == NULL) {
		return;
	}

        tcp = trace_get_tcp(packet);
	/* If the returned flow is new, you will probably want to allocate and
	 * initialise any custom data that you intend to track for the flow */
        if (is_new) {
                init_unknown_flow(f, dir, ts);
        	unk = (UnknownFlow *)f->extension;
	} else {
        	unk = (UnknownFlow *)f->extension;
		if (tcp && tcp->syn && !tcp->ack)
			unk->init_dir = dir;
	}

	/* Update our own byte and packet counters for reporting purposes */
	if (dir == 0) {
		unk->out_pkts += 1;
		unk->out_bytes += trace_get_payload_length(packet);
	}
	else {
		unk->in_bytes += trace_get_payload_length(packet);
		unk->in_pkts += 1;
	}


	/* Pass the packet into libprotoident so it can extract any info
	 * it needs from this packet */
	lpi_update_data(packet, &unk->lpi, dir);

        /* Update TCP state for TCP flows. The TCP state determines how long
	 * the flow can be idle before being expired by libflowmanager. For
	 * instance, flows for which we have only seen a SYN will expire much
	 * quicker than a TCP connection that has completed the handshake */
        if (tcp) {
                lfm_check_tcp_flags(f, tcp, dir, ts);
        }

        /* Tell libflowmanager to update the expiry time for this flow */
        lfm_update_flow_expiry_timeout(f, ts);


}

static void cleanup_signal(int sig) {
	(void)sig;
	done = 1;
}

static void usage(char *prog) {

	printf("Usage details for %s\n\n", prog);
	printf("%s [-l <mac>] [-T] [-b] [-d <dir>] [-f <filter>] [-R] [-H] inputURI [inputURI ...]\n\n", prog);
	printf("Options:\n");
	printf("  -l <mac>	Determine direction based on <mac> representing the 'inside' \n			portion of the network\n");
	printf("  -T		Use trace direction tags to determine direction\n");
	printf("  -b		Ignore flows that do not send data in both directions \n");
	printf("  -d <dir>	Ignore flows where the initial packet does not match the given \n   		direction\n");
	printf("  -f <filter>	Ignore flows that do not match the given BPF filter\n");
	printf("  -R 		Ignore flows involving private RFC 1918 address space\n");
	printf("  -H		Ignore flows that do not meet the criteria for an SPNAT hole\n");
	exit(0);

}

int main(int argc, char *argv[]) {

        libtrace_t *trace;
        libtrace_packet_t *packet;
	libtrace_filter_t *filter = NULL;
	struct sigaction sigact; 
        
	bool opt_true = true;
        bool opt_false = false;

        int i, opt;
        double ts;
	char *filterstring = NULL;
	int dir;
	bool ignore_rfc1918 = false;

        packet = trace_create_packet();
        if (packet == NULL) {
                perror("Creating libtrace packet");
                return -1;
        }

	while ((opt = getopt(argc, argv, "l:bHd:f:RhT")) != EOF) {
                switch (opt) {
			case 'l':
				local_mac = optarg;
				dir_method = DIR_METHOD_MAC;
				break;
			case 'b':
				require_both = true;
				break;
                        case 'd':
				dir = atoi(optarg);
				if (dir == 0)
					only_dir0 = true;
				if (dir == 1)
					only_dir1 = true;
				break;
			case 'f':
                                filterstring = optarg;
                                break;
			case 'R':
				ignore_rfc1918 = true;
				break;
			case 'H':
				nat_hole = true;
				break;
			case 'T':
				dir_method = DIR_METHOD_TRACE;
				break;
                	case 'h':
			default:
				usage(argv[0]);
		}

        }

        if (filterstring != NULL) {
                filter = trace_create_filter(filterstring);
        }

	if (local_mac != NULL) {
                if (convert_mac_string(local_mac, mac_bytes) < 0) {
                        fprintf(stderr, "Invalid MAC: %s\n", local_mac);
                        return 1;
                }
        }	

	/* This tells libflowmanager to ignore any flows where an RFC1918
	 * private IP address is involved */
        if (lfm_set_config_option(LFM_CONFIG_IGNORE_RFC1918, 
				&ignore_rfc1918) == 0)
                return -1;

	/* This tells libflowmanager not to replicate the TCP timewait
	 * behaviour where closed TCP connections are retained in the Flow
	 * map for an extra 2 minutes */
        if (lfm_set_config_option(LFM_CONFIG_TCP_TIMEWAIT, &opt_false) == 0)
                return -1;

	/* This tells libflowmanager not to utilise the fast expiry rules for
	 * short-lived UDP connections - these rules are experimental 
	 * behaviour not in line with recommended "best" practice */
	if (lfm_set_config_option(LFM_CONFIG_SHORT_UDP, &opt_false) == 0)
		return -1;


	sigact.sa_handler = cleanup_signal;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_RESTART;

	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);

	signal(SIGINT,&cleanup_signal);
	signal(SIGTERM,&cleanup_signal);

	if (lpi_init_library() == -1)
		return -1;

        for (i = optind; i < argc; i++) {

                fprintf(stderr, "%s\n", argv[i]);
                
		/* Bog-standard libtrace stuff for reading trace files */
		trace = trace_create(argv[i]);

                if (!trace) {
                        perror("Creating libtrace trace");
                        return -1;
                }

                if (trace_is_err(trace)) {
                        trace_perror(trace, "Opening trace file");
                        trace_destroy(trace);
                        continue;
                }

                if (filter && trace_config(trace, TRACE_OPTION_FILTER, filter) == -1) {
                        trace_perror(trace, "Configuring filter");
                        trace_destroy(trace);
                        return -1;
                }

                if (trace_start(trace) == -1) {
                        trace_perror(trace, "Starting trace");
                        trace_destroy(trace);
                        continue;
                }
                while (trace_read_packet(trace, packet) > 0) {
                        ts = trace_get_seconds(packet);
			per_packet(packet);
			if (done)
				break;

                }

		if (done)
			break;

                if (trace_is_err(trace)) {
                        trace_perror(trace, "Reading packets");
                        trace_destroy(trace);
                        continue;
                }

                trace_destroy(trace);

        }

        trace_destroy_packet(packet);
        expire_unknown_flows(ts, true);
	lpi_free_library();

        return 0;

}

