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
#include <libtrace_parallel.h>
#include <libflowmanager.h>
#include <libprotoident.h>

#include "../tools_common.h"

enum {
	DIR_METHOD_TRACE,
	DIR_METHOD_MAC,
	DIR_METHOD_PORT
};

libtrace_t *currenttrace;
static volatile int done = 0;

struct globalopts {

        int dir_method;
        bool only_dir0 ;
        bool only_dir1 ;
        bool require_both ;
        bool nat_hole ;
        bool ignore_rfc1918 ;
        char *local_mac ;
        uint8_t mac_bytes[6];
};

struct threadlocal {
        FlowManager *flowmanager;
};

/* This data structure is used to demonstrate how to use the 'extension' 
 * pointer to store custom data for a flow */
typedef struct ident {
	uint8_t init_dir;
	uint64_t in_bytes;
	uint64_t out_bytes;
	uint64_t in_pkts;
	uint64_t out_pkts;
	double start_ts;
        double end_ts;
	lpi_data_t lpi;
} IdentFlow;

static void *start_processing(libtrace_t *trace, libtrace_thread_t *thread,
                void *global) {

	bool opt_true = true;
        bool opt_false = false;
        struct globalopts *opts = (struct globalopts *)global;

        struct threadlocal *tl = (struct threadlocal *)malloc(sizeof(
                        struct threadlocal));
        tl->flowmanager = new FlowManager();

        /* This tells libflowmanager to ignore any flows where an RFC1918
	 * private IP address is involved */
        if (tl->flowmanager->setConfigOption(LFM_CONFIG_IGNORE_RFC1918, 
				&(opts->ignore_rfc1918)) == 0) {
                fprintf(stderr, "Failed to set IGNORE RFC 1918 option in libflowmanager\n");
        }

	/* This tells libflowmanager not to replicate the TCP timewait
	 * behaviour where closed TCP connections are retained in the Flow
	 * map for an extra 2 minutes */
        if (tl->flowmanager->setConfigOption(LFM_CONFIG_TCP_TIMEWAIT,
                                &opt_false) == 0) {
                fprintf(stderr, "Failed to set TCP TIMEWAIT option in libflowmanager\n");
        }

	/* This tells libflowmanager not to utilise the fast expiry rules for
	 * short-lived UDP connections - these rules are experimental 
	 * behaviour not in line with recommended "best" practice */
	if (tl->flowmanager->setConfigOption(LFM_CONFIG_SHORT_UDP,
                                &opt_false) == 0) {
                fprintf(stderr, "Failed to set SHORT UDP option in libflowmanager\n");
        }

        return tl;
}

static void *start_reporter(libtrace_t *trace, libtrace_thread_t *thread,
                void *global) {
        return NULL;
}

static void stop_reporter(libtrace_t *trace, libtrace_thread_t *thread,
                void *global, void *tls) {
        if (tls)
                free(tls);
}

/* Initialises the custom data for the given flow. Allocates memory for a
 * IdentFlow structure and ensures that the extension pointer points at
 * it.
 */
void init_ident_flow(Flow *f, uint8_t dir, double ts) {
	IdentFlow *ident = NULL;

	ident = (IdentFlow *)malloc(sizeof(IdentFlow));
	ident->init_dir = dir;
	ident->in_bytes = 0;
	ident->out_bytes = 0;
	ident->in_pkts = 0;
	ident->out_pkts = 0;
	ident->start_ts = ts;
        ident->end_ts = ts;
	lpi_init_data(&ident->lpi);
	f->extension = ident;
}

void dump_payload(lpi_data_t lpi, uint8_t dir, char *space, int spacelen) {

	int i;
	uint8_t *pl = (uint8_t *)(&(lpi.payload[dir]));
	uint32_t len = lpi.payload_len[dir];

        char ascii[4][5];

	for (i = 0; i < 4; i++) {
		if (*pl > 32 && *pl < 126) {
			snprintf(ascii[i], 5, "%c", *pl);
		} else {
			snprintf(ascii[i], 5, ".", NULL);
		}
		pl ++;
	}

        snprintf(space, spacelen - 1, "%08x %s%s%s%s %u",
                        ntohl(lpi.payload[dir]), ascii[0], ascii[1],
                        ascii[2], ascii[3], lpi.payload_len[dir]);


}

char *display_ident(Flow *f, IdentFlow *ident, struct globalopts *opts) {

        char s_ip[100];
	char c_ip[100];
        char pload_out[100];
        char pload_in[100];
        char *str;
	lpi_module_t *proto;

	if (opts->only_dir0 && ident->init_dir == 1)
		return NULL;
	if (opts->only_dir1 && ident->init_dir == 0)
		return NULL;
	if (opts->require_both) {
		if (ident->lpi.payload_len[0] == 0 || 
				ident->lpi.payload_len[1] == 0) {
			return NULL;
		}
	}

	if (opts->nat_hole) {
                if (ident->init_dir != 1)
                        return NULL;
                if (ident->lpi.payload_len[0] == 0 && ident->in_pkts <= 3)
                        return NULL;
        }

	proto = lpi_guess_protocol(&ident->lpi);

	f->id.get_server_ip_str(s_ip);
	f->id.get_client_ip_str(c_ip);

	dump_payload(ident->lpi, 0, pload_out, 500);
	dump_payload(ident->lpi, 1, pload_in, 500);
        str = (char *)malloc(750);
        snprintf(str, 1000, "%s %s %s %u %u %u %.3f %.3f %" PRIu64 " %" PRIu64 "%s %s\n",
			proto->name, s_ip, c_ip,
                        f->id.get_server_port(), f->id.get_client_port(),
                        f->id.get_protocol(), ident->start_ts,
                        ident->end_ts,
			ident->out_bytes, ident->in_bytes,
                        pload_out, pload_in);

        return str;
}

/* Expires all flows that libflowmanager believes have been idle for too
 * long. The exp_flag variable tells libflowmanager whether it should force
 * expiry of all flows (e.g. if you have reached the end of the program and
 * want the stats for all the still-active flows). Otherwise, only flows
 * that have been idle for longer than their expiry timeout will be expired.
 */
void expire_ident_flows(libtrace_t *trace, libtrace_thread_t *thread,
                struct globalopts *opts, FlowManager *fm, double ts,
                bool exp_flag) {
        Flow *expired;
	lpi_module_t *proto;
        char *result = NULL;

        /* Loop until libflowmanager has no more expired flows available */
	while ((expired = fm->expireNextFlow(ts, exp_flag)) != NULL) {

                IdentFlow *ident = (IdentFlow *)expired->extension;
		result = display_ident(expired, ident, opts);
                if (result) {
                        trace_publish_result(trace, thread, ident->end_ts,
                                        (libtrace_generic_t){.ptr=result},
                                        RESULT_USER);
                }
		/* Don't forget to free our custom data structure */
                free(ident);

                fm->releaseFlow(expired);
        }
}

static void stop_processing(libtrace_t *trace, libtrace_thread_t *thread,
                void *global, void *tls) {

        struct globalopts *opts = (struct globalopts *)global;
        struct threadlocal *tl = (struct threadlocal *)tls;

        expire_ident_flows(trace, thread, opts, tl->flowmanager, 0, true);
        delete(tl->flowmanager);
        free(tl);


}


static void per_result(libtrace_t *trace, libtrace_thread_t *sender,
                void *global, void *tls, libtrace_result_t *result) {

        char *resultstr;

        if (result->type != RESULT_USER)
                return;

        resultstr = (char *)result->value.ptr;
        printf("%s", resultstr);
        free(resultstr);

}

static libtrace_packet_t *per_packet(libtrace_t *trace,
                libtrace_thread_t *thread, void *global, void *tls,
                libtrace_packet_t *packet) {

        Flow *f;
        IdentFlow *ident = NULL;
        uint8_t dir;
        bool is_new = false;

        libtrace_tcp_t *tcp = NULL;
        void *l3;
	double ts;

        uint16_t l3_type;
        struct globalopts *opts = (struct globalopts *)global;
        struct threadlocal *tl = (struct threadlocal *)tls;

        /* Libflowmanager only deals with IP traffic, so ignore anything
	 * that does not have an IP header */
        l3 = trace_get_layer3(packet, &l3_type, NULL);
        if (l3_type != TRACE_ETHERTYPE_IP && l3_type != TRACE_ETHERTYPE_IPV6) 
		return packet;
        if (l3 == NULL) return packet;

	/* Expire all suitably idle flows */
        ts = trace_get_seconds(packet);
        expire_ident_flows(trace, thread, opts, tl->flowmanager, ts, false);

	/* Determine packet direction */
	if (opts->dir_method == DIR_METHOD_TRACE) {
		dir = trace_get_direction(packet);
	}
	if (opts->dir_method == DIR_METHOD_MAC) {
		dir = mac_get_direction(packet, opts->mac_bytes);
	}
	if (opts->dir_method == DIR_METHOD_PORT) {
		dir = port_get_direction(packet);
	}

	if (dir != 0 && dir != 1)
		return packet;

        /* Match the packet to a Flow - this will create a new flow if
	 * there is no matching flow already in the Flow map and set the
	 * is_new flag to true. */
        f = tl->flowmanager->matchPacketToFlow(packet, dir, &is_new);

	/* Libflowmanager did not like something about that packet - best to
	 * just ignore it and carry on */
        if (f == NULL) {
		return packet;
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
                if (ident->end_ts < ts)
                        ident->end_ts = ts;
	}

	/* Update our own byte and packet counters for reporting purposes */
	if (dir == 0) {
		ident->out_pkts += 1;
		ident->out_bytes += trace_get_payload_length(packet);
	}
	else {
		ident->in_bytes += trace_get_payload_length(packet);
		ident->in_pkts += 1;
	}


	/* Pass the packet into libprotoident so it can extract any info
	 * it needs from this packet */
	lpi_update_data(packet, &ident->lpi, dir);

	assert(f);
        /* Tell libflowmanager to update the expiry time for this flow */
        tl->flowmanager->updateFlowExpiry(f, packet, dir, ts);

        return packet;
}

static void cleanup_signal(int sig) {
	(void)sig;
        if (!done) {
                trace_pstop(currenttrace);
        	done = 1;
        }
}

static void usage(char *prog) {

	printf("Usage details for %s\n\n", prog);
	printf("%s [-l <mac>] [-T] [-b] [-d <dir>] [-f <filter>] [-R] [-H] [-t <threads>] inputURI [inputURI ...]\n\n", prog);
	printf("Options:\n");
	printf("  -l <mac>	Determine direction based on <mac> representing the 'inside' \n			portion of the network\n");
	printf("  -T		Use trace direction tags to determine direction\n");
	printf("  -b		Ignore flows that do not send data in both directions \n");
	printf("  -d <dir>	Ignore flows where the initial packet does not match the given \n   		direction\n");
	printf("  -f <filter>	Ignore flows that do not match the given BPF filter\n");
	printf("  -R 		Ignore flows involving private RFC 1918 address space\n");
	printf("  -H		Ignore flows that do not meet the criteria for an SPNAT hole\n");
        printf("  -t <threads>  Share the workload over the given number of threads\n");
	exit(0);

}

int main(int argc, char *argv[]) {

	libtrace_filter_t *filter = NULL;
	struct sigaction sigact; 
        struct globalopts opts;
        int i, opt;
        double ts;
	char *filterstring = NULL;
	int dir;
        int threads = 1;

        libtrace_callback_set_t *processing, *reporter;

        opts.dir_method = DIR_METHOD_PORT;
        opts.only_dir0 = false;
        opts.only_dir1 = false;
        opts.require_both = false;
        opts.nat_hole = false;
        opts.ignore_rfc1918 = false;
        opts.local_mac = NULL;

        processing = trace_create_callback_set();
        trace_set_starting_cb(processing, start_processing);
        trace_set_stopping_cb(processing, stop_processing);
        trace_set_packet_cb(processing, per_packet);

        reporter = trace_create_callback_set();
        trace_set_starting_cb(reporter, start_reporter);
        trace_set_stopping_cb(reporter, stop_reporter);
        trace_set_result_cb(reporter, per_result);

	while ((opt = getopt(argc, argv, "l:bHd:f:RhTt:")) != EOF) {
                switch (opt) {
			case 'l':
				opts.local_mac = optarg;
				opts.dir_method = DIR_METHOD_MAC;
				break;
			case 'b':
				opts.require_both = true;
				break;
                        case 'd':
				dir = atoi(optarg);
				if (dir == 0)
					opts.only_dir0 = true;
				if (dir == 1)
					opts.only_dir1 = true;
				break;
			case 'f':
                                filterstring = optarg;
                                break;
			case 'R':
				opts.ignore_rfc1918 = true;
				break;
			case 'H':
				opts.nat_hole = true;
				break;
			case 'T':
				opts.dir_method = DIR_METHOD_TRACE;
				break;
                        case 't':
                                threads = atoi(optarg);
                                if (threads <= 0)
                                        threads = 1;
                                break;
                	case 'h':
			default:
				usage(argv[0]);
		}

        }

        if (filterstring != NULL) {
                filter = trace_create_filter(filterstring);
        }

	if (opts.local_mac != NULL) {
                if (convert_mac_string(opts.local_mac, opts.mac_bytes) < 0) {
                        fprintf(stderr, "Invalid MAC: %s\n", opts.local_mac);
                        return 1;
                }
        }

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
                if (done)
                        break;
                fprintf(stderr, "%s\n", argv[i]);
                
		/* Bog-standard libtrace stuff for reading trace files */
		currenttrace = trace_create(argv[i]);

                if (!currenttrace) {
                        perror("Creating libtrace trace");
                        return -1;
                }

                if (trace_is_err(currenttrace)) {
                        trace_perror(currenttrace, "Opening trace file");
                        trace_destroy(currenttrace);
                        continue;
                }

                if (filter && trace_config(currenttrace, TRACE_OPTION_FILTER, filter) == -1) {
                        trace_perror(currenttrace, "Configuring filter");
                        trace_destroy(currenttrace);
                        return -1;
                }

                trace_set_perpkt_threads(currenttrace, threads);

                trace_set_combiner(currenttrace, &combiner_unordered,
                        (libtrace_generic_t){0});

                trace_set_hasher(currenttrace, HASHER_BIDIRECTIONAL, NULL, NULL);

                if (trace_pstart(currenttrace, &opts, processing, reporter) == -1) {
                        trace_perror(currenttrace, "Starting trace");
                        trace_destroy(currenttrace);
                        continue;
                }

                trace_join(currenttrace);
                trace_destroy(currenttrace);

        }

        trace_destroy_callback_set(processing);
        trace_destroy_callback_set(reporter);
	lpi_free_library();

        return 0;

}

