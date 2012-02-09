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
#include <string.h>

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

char *local_mac = NULL;
uint8_t mac_bytes[6];

static volatile int done = 0;

uint64_t in_pkt_count[LPI_PROTO_LAST];
uint64_t out_pkt_count[LPI_PROTO_LAST];
uint64_t in_byte_count[LPI_PROTO_LAST];
uint64_t out_byte_count[LPI_PROTO_LAST];
uint64_t in_flow_count[LPI_PROTO_LAST];
uint64_t out_flow_count[LPI_PROTO_LAST];
	
uint32_t report_freq = 60;

typedef struct live {
	uint8_t init_dir;
	uint64_t in_pkts;
	uint64_t out_pkts;
	uint64_t in_wbytes;
	uint64_t in_pbytes;
	uint64_t out_wbytes;
	uint64_t out_pbytes;
	double start_ts;
	lpi_data_t lpi;
	lpi_module_t *proto;
} LiveFlow;

/* Initialises the custom data for the given flow. Allocates memory for a
 * LiveFlow structure and ensures that the extension pointer points at
 * it.
 */
void init_live_flow(Flow *f, uint8_t dir, double ts) {
	LiveFlow *live = NULL;

	live = (LiveFlow *)malloc(sizeof(LiveFlow));
	live->init_dir = dir;
	live->in_wbytes = 0;
	live->out_wbytes = 0;
	live->in_pbytes = 0;
	live->out_pbytes = 0;
	live->in_pkts = 0;
	live->out_pkts = 0;
	live->start_ts = ts;
	lpi_init_data(&live->lpi);
	f->extension = live;
	live->proto = NULL;
}

void reset_counters() {

	memset(in_pkt_count, 0, LPI_PROTO_LAST * sizeof(uint64_t));
	memset(out_pkt_count, 0, LPI_PROTO_LAST * sizeof(uint64_t));
	memset(in_byte_count, 0, LPI_PROTO_LAST * sizeof(uint64_t));
	memset(out_byte_count, 0, LPI_PROTO_LAST * sizeof(uint64_t));
	memset(in_flow_count, 0, LPI_PROTO_LAST * sizeof(uint64_t));
	memset(out_flow_count, 0, LPI_PROTO_LAST * sizeof(uint64_t));

}

static inline FILE *open_fd(const char *fname) {
	char buf[10];
	
	FILE *fd = fopen(fname, "a+");
	if (!fd) {
		perror("fopen");
		exit(1);
	}
	
	/* The file is empty, i.e. newly created, we need to write our
	 * header at the start of the file */ 
	if (fread(buf, 1, 10, fd) != 10) {
		if (ferror(fd)) {
			perror("fread");
			exit(1);
		}
		assert(feof(fd));


		fprintf(fd, "TS ");

		for (int i = 0; i < LPI_PROTO_LAST; i++) {
			fprintf(fd, "%s ", lpi_print((lpi_protocol_t)i));
		}

		fprintf(fd, "\n");
	}
	
	return fd;
}

void dump_counter_array(double ts, FILE *fd, uint64_t *counter, bool kbps) {

	int i;
	double bitrate = 0.0;

	fprintf(fd, "%.0f ", ts);

	for (i = 0; i < LPI_PROTO_LAST; i++) {
		
		if (kbps) {
			bitrate = ((float)counter[i]) * 8.0 / 1024.0 / report_freq;
			fprintf(fd, "%.3f ", bitrate);
		} else {
			fprintf(fd, "%" PRIu64 " ", counter[i]);
		}
	}

	fprintf(fd, "\n");
	fflush(fd);
}

void dump_counters(double ts) {

	static FILE *in_pkt_fd = NULL;
	static FILE *out_pkt_fd = NULL;
	static FILE *in_byte_fd = NULL;
	static FILE *out_byte_fd = NULL;
	static FILE *in_flow_fd = NULL;
	static FILE *out_flow_fd = NULL;

	if (in_pkt_fd == NULL) {
		in_pkt_fd = open_fd("packets_in");
	}
	if (out_pkt_fd == NULL) {
		out_pkt_fd = open_fd("packets_out");
	}
	if (in_byte_fd == NULL) {
		in_byte_fd = open_fd("bytes_in");
	}
	if (out_byte_fd == NULL) {
		out_byte_fd = open_fd("bytes_out");
	}
	if (in_flow_fd == NULL) {
		in_flow_fd = open_fd("flows_in");
	}
	if (out_flow_fd == NULL) {
		out_flow_fd = open_fd("flows_out");
	}

	dump_counter_array(ts, in_pkt_fd, in_pkt_count, false);
	dump_counter_array(ts, out_pkt_fd, out_pkt_count, false);
	dump_counter_array(ts, in_byte_fd, in_byte_count, true);
	dump_counter_array(ts, out_byte_fd, out_byte_count, true);
	dump_counter_array(ts, in_flow_fd, in_flow_count, false);
	dump_counter_array(ts, out_flow_fd, out_flow_count, false);

}

bool should_guess(LiveFlow *live, uint32_t plen, uint8_t dir) {

	if (live->out_pbytes == 0 && live->in_pbytes == 0 && live->proto == NULL)
		return true;

	if (plen == 0)
		return false;
	
	if (dir == 0 && live->out_pbytes == plen)
		return true;
	if (dir == 1 && live->in_pbytes == plen)
		return true;

	return false;	
}

void update_protocol_counters(LiveFlow *live, uint32_t wlen, uint32_t plen, 
		uint8_t dir) {

	lpi_module_t *old_proto = live->proto;

	if (should_guess(live, plen, dir)) {
		live->proto = lpi_guess_protocol(&live->lpi);
	}

	if (old_proto == live->proto) {
		if (dir == 0) {
			out_byte_count[live->proto->protocol] += wlen;
			out_pkt_count[live->proto->protocol] += 1;
		} else {
			in_byte_count[live->proto->protocol] += wlen;
			in_pkt_count[live->proto->protocol] += 1;
		}
	} else if (old_proto == NULL) {
		
		if (live->init_dir == 0)
			out_flow_count[live->proto->protocol] += 1;
		else
			in_flow_count[live->proto->protocol] += 1;
			
		out_byte_count[live->proto->protocol] += live->out_wbytes;
		out_pkt_count[live->proto->protocol] += live->out_pkts;
		in_byte_count[live->proto->protocol] += live->in_wbytes;
		in_pkt_count[live->proto->protocol] += live->in_pkts;
	
	} else {

		/* Protocol has "changed" - subtract whatever we would have
		 * inserted into the previous protocol counter and shift those
		 * values into the new one */

		if (live->init_dir == 0) {
			out_flow_count[old_proto->protocol] --;
			out_flow_count[live->proto->protocol] ++;
		} else {
			in_flow_count[old_proto->protocol] --;
			in_flow_count[live->proto->protocol] ++;
		}


		if (dir == 0) {

			assert(live->out_wbytes >= wlen);
			out_byte_count[old_proto->protocol] -= (live->out_wbytes - wlen);
			out_pkt_count[old_proto->protocol] -= (live->out_pkts - 1);
			in_byte_count[old_proto->protocol] -= (live->in_wbytes);
			in_pkt_count[old_proto->protocol] -= (live->in_pkts);
		} else {
			assert(live->in_wbytes >= wlen);
			out_byte_count[old_proto->protocol] -= (live->out_wbytes);
			out_pkt_count[old_proto->protocol] -= (live->out_pkts);
			in_byte_count[old_proto->protocol] -= (live->in_wbytes - wlen);
			in_pkt_count[old_proto->protocol] -= (live->in_pkts - 1);

		}
		out_byte_count[live->proto->protocol] += live->out_wbytes;
		out_pkt_count[live->proto->protocol] += live->out_pkts;
		in_byte_count[live->proto->protocol] += live->in_wbytes;
		in_pkt_count[live->proto->protocol] += live->in_pkts;
	}

}

/* Expires all flows that libflowmanager believes have been idle for too
 * long. The exp_flag variable tells libflowmanager whether it should force
 * expiry of all flows (e.g. if you have reached the end of the program and
 * want the stats for all the still-active flows). Otherwise, only flows
 * that have been idle for longer than their expiry timeout will be expired.
 */
void expire_live_flows(double ts, bool exp_flag) {
        Flow *expired;

        /* Loop until libflowmanager has no more expired flows available */
	while ((expired = lfm_expire_next_flow(ts, exp_flag)) != NULL) {

                LiveFlow *live = (LiveFlow *)expired->extension;
		
		/* Don't forget to free our custom data structure */
                free(live);

		/* VERY IMPORTANT: delete the Flow structure itself, even
		 * though we did not directly allocate the memory ourselves */
                delete(expired);
        }
}


void per_packet(libtrace_packet_t *packet) {

        Flow *f;
        LiveFlow *live = NULL;
        uint8_t dir;
        bool is_new = false;

        libtrace_tcp_t *tcp = NULL;
        void *l3;
	double ts;

        uint16_t l3_type;

        l3 = trace_get_layer3(packet, &l3_type, NULL);
        if (l3_type != TRACE_ETHERTYPE_IP && l3_type != TRACE_ETHERTYPE_IPV6) 
		return;
        if (l3 == NULL) return;

	/* Expire all suitably idle flows */
        ts = trace_get_seconds(packet);
        expire_live_flows(ts, false);

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
                init_live_flow(f, dir, ts);
        	live = (LiveFlow *)f->extension;
	} else {
        	live = (LiveFlow *)f->extension;
		if (tcp && tcp->syn && !tcp->ack)
			live->init_dir = dir;
	}

	if (dir == 0) {
		live->out_pbytes += trace_get_payload_length(packet);
		live->out_wbytes += trace_get_wire_length(packet);
		live->out_pkts += 1;
	} else {
		live->in_pbytes += trace_get_payload_length(packet);
		live->in_wbytes += trace_get_wire_length(packet);
		live->in_pkts += 1;
	}

	/* Pass the packet into libprotolive so that it can extract any
	 * info it needs from this packet */
	lpi_update_data(packet, &live->lpi, dir);

	update_protocol_counters(live, trace_get_wire_length(packet), 
			trace_get_payload_length(packet), dir);	


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
	done=1;
}

static void usage(char *prog) {

        printf("Usage details for %s\n\n", prog);
        printf("%s [-i <freq>] [-l <mac] [-T] [-f <filter>] [-R] [-H] inputURI [inputURI ...]\n\n", prog);
        printf("Options:\n");
	printf("  -l <mac>      Determine direction based on <mac> representing the 'inside' \n                 portion of the network\n");
	printf("  -T            Use trace direction tags to determine direction\n");
        printf("  -f <filter>   Ignore flows that do not match the given BPF filter\n");
        printf("  -R            Ignore flows involving private RFC 1918 address space\n");
        printf("  -i <freq>	Report statistics every <freq> seconds\n");
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

	double next_report = 0.0;

	uint32_t max_reports = 0;
	uint32_t reports_done = 0;

        packet = trace_create_packet();
        if (packet == NULL) {
                perror("Creating libtrace packet");
                return -1;
        }

	while ((opt = getopt(argc, argv, "i:f:Rhl:T")) != EOF) {
                switch (opt) {
			case 'l':
                                local_mac = optarg;
                                dir_method = DIR_METHOD_MAC;
                                break;
			case 'T':
                                dir_method = DIR_METHOD_TRACE;
                                break;
			case 'f':
                                filterstring = optarg;
                                break;
			case 'R':
				ignore_rfc1918 = true;
				break;
			case 'i':
				report_freq = atoi(optarg);
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

	reset_counters();

	if (optind == argc) {
		fprintf(stderr, "No input sources specified!\n");
		usage(argv[0]);
	}

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
			if (next_report == 0.0 && ts != 0.0) {
				next_report = ts + report_freq;
			}

			while (ts > next_report) {
				dump_counters(next_report);
				reset_counters();
				next_report += report_freq;
				reports_done ++;

				if (max_reports != 0 && 
						reports_done >= max_reports)
					done = 1;
			}

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
        expire_live_flows(ts, true);
	lpi_free_library();

        return 0;

}

