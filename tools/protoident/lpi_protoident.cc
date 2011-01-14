/*
 * Simple program that uses libprotoident to identify the protocol of all flows
 * in a trace file.
 *
 * Author: Shane Alcock
 */

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <libtrace.h>
#include <libflowmanager.h>
#include <libprotoident.h>

bool only_dir0 = false;
bool only_dir1 = false;

bool require_both = false;
bool nat_hole = false;

typedef struct ident {
	uint8_t init_dir;
	uint64_t in_pkts;
	uint64_t out_pkts;
	uint64_t in_bytes;
	uint64_t out_bytes;
	double start_ts;
	lpi_data_t lpi;
} IdentFlow;

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
	lpi_init_data(&ident->lpi);
	f->extension = ident;
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

void display_ident(Flow *f, IdentFlow *ident) {

        char ip[50];
        char str[1000];
        struct in_addr in;
	lpi_protocol_t proto;

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

	if (nat_hole) {
		if (ident->init_dir != 1)
			return;
		if (ident->lpi.payload_len[0] == 0 && ident->in_pkts <= 3)
			return;
	}

	proto = lpi_guess_protocol(&ident->lpi);

        in.s_addr = f->id.get_server_ip();
        snprintf(ip, 1000, "%s", inet_ntoa(in));

        in.s_addr = f->id.get_client_ip();
        snprintf(str, 1000, "%s %s %s %u %u %u %.3f %lu %lu", 
			lpi_print(proto), ip, inet_ntoa(in),
                        f->id.get_server_port(), f->id.get_client_port(),
                        f->id.get_protocol(), ident->start_ts,
			ident->out_bytes, ident->in_bytes);

	printf("%s ", str);

	dump_payload(ident->lpi, 0);
	dump_payload(ident->lpi, 1);
	printf("\n");


}

/* Expires all flows that libflowmanager believes have been idle for too
 * long. The exp_flag variable tells libflowmanager whether it should force
 * expiry of all flows (e.g. if you have reached the end of the program and
 * want the stats for all the still-active flows). Otherwise, only flows
 * that have been idle for longer than their expiry timeout will be expired.
 */
void expire_ident_flows(double ts, bool exp_flag) {
        Flow *expired;

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


void per_packet(libtrace_packet_t *packet) {

        Flow *f;
        IdentFlow *ident = NULL;
        uint8_t dir;
        bool is_new = false;

        libtrace_tcp_t *tcp = NULL;
        libtrace_ip_t *ip = NULL;
        double ts;

        uint16_t l3_type;

	uint16_t src_port;
	uint16_t dst_port;

        /* Libflowmanager only deals with IP traffic, so ignore anything
	 * that does not have an IP header */
        ip = (libtrace_ip_t *)trace_get_layer3(packet, &l3_type, NULL);
        if (l3_type != 0x0800) return;
        if (ip == NULL) return;

	/* Expire all suitably idle flows */
        ts = trace_get_seconds(packet);
        expire_ident_flows(ts, false);

	/* Many trace formats do not support direction tagging (e.g. PCAP), so
	 * using trace_get_direction() is not an ideal approach. The one we
	 * use here is not the nicest, but it is pretty consistent and 
	 * reliable. Feel free to replace this with something more suitable
	 * for your own needs!.
	 */
	
	src_port = trace_get_source_port(packet);
	dst_port = trace_get_destination_port(packet);

	if (src_port == dst_port) {
		if (ip->ip_src.s_addr < ip->ip_dst.s_addr)
			dir = 0;
		else
			dir = 1;
	} else {
		if (trace_get_server_port(ip->ip_p, src_port, dst_port) == USE_SOURCE)
			dir = 0;
		else
			dir = 1;
	}

        /* Ignore packets where the IP addresses are the same - something is
         * probably screwy and it's REALLY hard to determine direction */
        if (ip->ip_src.s_addr == ip->ip_dst.s_addr)
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

	
	/* Update our own byte and packet counters for reporting purposes */
	if (dir == 0) {
		ident->out_bytes += trace_get_payload_length(packet);
		ident->out_pkts += 1;
	}
	else {
		ident->in_bytes += trace_get_payload_length(packet);
		ident->in_pkts += 1;
	}

	/* Pass the packet into libprotoident so that it can extract any
	 * info it needs from this packet */
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


int main(int argc, char *argv[]) {

        libtrace_t *trace;
        libtrace_packet_t *packet;
	libtrace_filter_t *filter = NULL;

        bool opt_true = true;
        bool opt_false = false;

        int i, opt;
        double ts;
	char *filterstring = NULL;
	int dir;

        packet = trace_create_packet();
        if (packet == NULL) {
                perror("Creating libtrace packet");
                return -1;
        }

	while ((opt = getopt(argc, argv, "bHd:f:")) != EOF) {
                switch (opt) {
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
			case 'H':
				nat_hole = true;
				break;
                }
        }

        if (filterstring != NULL) {
                filter = trace_create_filter(filterstring);
        }


	/* This tells libflowmanager to ignore any flows where an RFC1918
	 * private IP address is involved */
        if (lfm_set_config_option(LFM_CONFIG_IGNORE_RFC1918, &opt_true) == 0)
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

                }

                if (trace_is_err(trace)) {
                        trace_perror(trace, "Reading packets");
                        trace_destroy(trace);
                        continue;
                }

                trace_destroy(trace);

        }

        trace_destroy_packet(packet);
        expire_ident_flows(ts, true);

        return 0;

}

