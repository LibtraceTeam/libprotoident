/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011-2015 The University of Waikato, Hamilton, New Zealand.
 * Author: Shane Alcock
 *
 * With contributions from:
 *      Aaron Murrihy
 *      Donald Neal
 *      Paweł Foremski <pjf@iitis.pl> (ARFF statistics)
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
 * $Id: lpi_protoident.cc 102 2011-10-18 00:43:04Z salcock $
 */

/*
 * Program flow
 *
 * main()
 * - parse command-line options
 * - initialize libraries
 * - read packet by packet in loop, call per_packet() for each

 * per_packet()
 * - skip non-IP traffic
 * - call garbage collector - expire_ident_flows() - may print output
 * - match packet to flow
 * - update flow statistics
 * - identify the packet, call libprotoident
 *
 * expire_ident_flows()
 * - loop through all expired flows and call display_ident() for each of them
 *
 */

#define __STDC_FORMAT_MACROS
#define __STDC_LIMIT_MACROS

#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

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

static volatile int done = 0;

char *local_mac = NULL;
uint8_t mac_bytes[6];

struct ident_stats {
	uint64_t pkts;
	uint64_t bytes;

	uint16_t pktlen_min;
	uint16_t pktlen_max;
	double pktlen_mean;
	double pktlen_std;

	uint32_t iat_min;
	uint32_t iat_max;
	double iat_mean;
	double iat_std;
};

/* This data structure is used to demonstrate how to use the 'extension' 
 * pointer to store custom data for a flow */
typedef struct ident {
	uint8_t init_dir;

	struct ident_stats in;
	struct ident_stats out;

	double start_ts;
	double last_ts;

	lpi_data_t lpi;
} IdentFlow;

/* Initialises the custom data for the given flow. Allocates memory for a
 * IdentFlow structure and ensures that the extension pointer points at
 * it.
 */
void init_ident_flow(Flow *f, uint8_t dir, double ts)
{
	IdentFlow *ident = NULL;

	ident = (IdentFlow *) malloc(sizeof(IdentFlow));

	memset(ident, 0, sizeof(IdentFlow));
	ident->init_dir = dir;

	ident->start_ts = ts;
	ident->last_ts = ts;

	ident->in.pktlen_min = UINT16_MAX;
	ident->out.pktlen_min = UINT16_MAX;

	ident->in.iat_min = UINT32_MAX;
	ident->out.iat_min = UINT32_MAX;

	lpi_init_data(&ident->lpi);

	f->extension = ident;
}

void display_ident(Flow *f, IdentFlow *ident)
{
	char s_ip[500];
	char c_ip[500];
	char str[1000];
	lpi_module_t *proto;
	struct ident_stats *is;
	int i;

	if (only_dir0 && ident->init_dir == 1)
		return;
	if (only_dir1 && ident->init_dir == 0)
		return;
	if (require_both) {
		if (ident->lpi.payload_len[0] == 0 ||
		    ident->lpi.payload_len[1] == 0) {
			return;
		}
	}

	proto = lpi_guess_protocol(&ident->lpi);

	f->id.get_server_ip_str(s_ip);
	f->id.get_client_ip_str(c_ip);

	/* basic statistics */
	printf("%s,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64,
		proto->name, f->id.get_protocol(),
		ident->out.pkts, ident->out.bytes, ident->in.pkts, ident->in.bytes);

	/* print packet length statistics */
	is = &ident->out;
	for (i = 0; i < 2; i++) {
		if (is->pkts == 0) {
			printf(",0,0,0,0");
		} else {
			printf(",%u,%.0f,%u,%.0f",
				is->pktlen_min, is->pktlen_mean, is->pktlen_max,
				sqrt(is->pktlen_std / is->pkts));
		}
		is = &ident->in;
	}

	/* print inter-arrival time statistics */
	is = &ident->out;
	for (i = 0; i < 2; i++) {
		if (is->pkts == 0) {
			printf(",0,0,0,0");
		} else {
			printf(",%u,%.0f,%u,%.0f",
				is->iat_min, is->iat_mean, is->iat_max,
				sqrt(is->iat_std / is->pkts));
		}
		is = &ident->in;
	}

	/* print total flow duration */
	printf(",%.0f", (ident->last_ts - ident->start_ts) * 1000000.0);

	/* print flow start time */
	printf(",%f", ident->start_ts);

	printf("\n");
}

/* Expires all flows that libflowmanager believes have been idle for too
 * long. The exp_flag variable tells libflowmanager whether it should force
 * expiry of all flows (e.g. if you have reached the end of the program and
 * want the stats for all the still-active flows). Otherwise, only flows
 * that have been idle for longer than their expiry timeout will be expired.
 */
void expire_ident_flows(double ts, bool exp_flag)
{
	Flow *expired;
	lpi_module_t *proto;

	/* Loop until libflowmanager has no more expired flows available */
	while ((expired = lfm_expire_next_flow(ts, exp_flag)) != NULL) {

		IdentFlow *ident = (IdentFlow *)expired->extension;

		display_ident(expired, ident);
		/* Don't forget to free our custom data structure */
		free(ident);

		/* VERY IMPORTANT: delete the Flow structure itself, even
		 * though we did not directly allocate the memory ourselves */
		delete(expired);
	}
}

/** Update flow statistics */
void per_packet_flow(libtrace_packet_t *packet, IdentFlow *ident, int dir, 
		double ts)
{
	struct ident_stats *is;
	int pktlen;
	uint32_t iat;
	double diff, mean, iatd;

	is = (dir == 0 ? &ident->out : &ident->in);

	/* basic statistics */
	pktlen = trace_get_payload_length(packet);
	is->pkts++;
	is->bytes += pktlen;

	/* packet length statistics */
	if (pktlen < is->pktlen_min)
		is->pktlen_min = pktlen;
	if (pktlen > is->pktlen_max)
		is->pktlen_max = pktlen;

	diff = pktlen - is->pktlen_mean;
	mean = is->pktlen_mean + diff / is->pkts;
	is->pktlen_std += diff * (pktlen - mean);
	is->pktlen_mean = mean;

	/* packet inter-arrival time */
	iatd = ts - ident->last_ts;
	if (iatd < 0) {
		iat = 0;
	} else {
		/* convert to us */
		iatd *= 1000000;

		if (iatd > UINT32_MAX)
			iat = UINT32_MAX;
		else
			iat = iatd;
	}

	if (iat < is->iat_min)
		is->iat_min = iat;
	if (iat > is->iat_max)
		is->iat_max = iat;

	diff = iat - is->iat_mean;
	mean = is->iat_mean + diff / is->pkts;
	is->iat_std += diff * (iat - mean);
	is->iat_mean = mean;

	/* update timestamp of last packet */
	ident->last_ts = ts;
}

/** This function receives each packet from libtrace */
void per_packet(libtrace_packet_t *packet)
{
	Flow *f;
	IdentFlow *ident = NULL;
	uint8_t dir;
	bool is_new = false;

	libtrace_tcp_t *tcp = NULL;
	void *l3;
	double ts;

	uint16_t l3_type;

	/* Libflowmanager only deals with IP traffic, so ignore anything
	 * that does not have an IP header */
	l3 = trace_get_layer3(packet, &l3_type, NULL);
	if (l3_type != TRACE_ETHERTYPE_IP && l3_type != TRACE_ETHERTYPE_IPV6)
		return;
	if (l3 == NULL) return;

	/* Expire all suitably idle flows */
	ts = trace_get_seconds(packet);
	expire_ident_flows(ts, false);

	/* Determine packet direction
	 * 0 is output, 1 is input */
	switch (dir_method) {
		case DIR_METHOD_TRACE:
			dir = trace_get_direction(packet);
			break;
		case DIR_METHOD_MAC:
			dir = mac_get_direction(packet, mac_bytes);
			break;
		case DIR_METHOD_PORT:
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
		init_ident_flow(f, dir, ts);
		ident = (IdentFlow *)f->extension;
	} else {
		ident = (IdentFlow *)f->extension;
		if (tcp && tcp->syn && !tcp->ack)
			ident->init_dir = dir;
	}

	/* Update flow statistics in ident */
	per_packet_flow(packet, ident, dir, ts);

	/* Pass the packet into libprotoident so it can extract any info
	 * it needs from this packet */
	lpi_update_data(packet, &ident->lpi, dir);

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

static void cleanup_signal(int sig)
{
	(void)sig;
	done = 1;
}

static void usage(char *prog)
{
	printf("Usage details for %s\n\n", prog);
	printf("%s [-l <mac>] [-T] [-b] [-d <dir>] [-f <filter>] [-R] inputURI [inputURI ...]\n\n", prog);
	printf("Options:\n");
	printf("  -l <mac>     Determine direction based on <mac> representing the 'inside'\n");
	printf("               portion of the network\n");
	printf("  -T           Use trace direction tags to determine direction\n");
	printf("  -b           Ignore flows that do not send data in both directions \n");
	printf("  -d <dir>     Ignore flows where the initial packet does not match the given\n");
	printf("               direction\n");
	printf("  -f <filter>  Ignore flows that do not match the given BPF filter\n");
	printf("  -R           Ignore flows involving private RFC 1918 address space\n");
	exit(0);
}

int main(int argc, char *argv[])
{
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

	while ((opt = getopt(argc, argv, "l:bd:f:RhT")) != EOF) {
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
	if (lfm_set_config_option(LFM_CONFIG_IGNORE_RFC1918, &ignore_rfc1918) == 0)
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

		/* printf arff file header */
		printf("@relation '%s'\n", argv[i]);
		printf("\n");
		printf("@attribute label string\n");
		printf("@attribute protocol numeric\n");
		printf("@attribute fpackets numeric\n");
		printf("@attribute fbytes numeric\n");
		printf("@attribute bpackets numeric\n");
		printf("@attribute bbytes numeric\n");
		printf("@attribute minfpktl numeric\n");
		printf("@attribute meanfpktl numeric\n");
		printf("@attribute maxfpktl numeric\n");
		printf("@attribute stdfpktl numeric\n");
		printf("@attribute minbpktl numeric\n");
		printf("@attribute meanbpktl numeric\n");
		printf("@attribute maxbpktl numeric\n");
		printf("@attribute stdbpktl numeric\n");
		printf("@attribute minfiat numeric\n");
		printf("@attribute meanfiat numeric\n");
		printf("@attribute maxfiat numeric\n");
		printf("@attribute stdfiat numeric\n");
		printf("@attribute minbiat numeric\n");
		printf("@attribute meanbiat numeric\n");
		printf("@attribute maxbiat numeric\n");
		printf("@attribute stdbiat numeric\n");
		printf("@attribute duration numeric\n");
		printf("@attribute timestamp numeric\n");
		printf("\n");
		printf("@data\n");

		while (trace_read_packet(trace, packet) > 0) {
			ts = trace_get_seconds(packet);
			per_packet(packet);
			if (done) {
				break;
			}
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
	if (!done)
		expire_ident_flows(ts, true);
	lpi_free_library();

	return 0;
}
