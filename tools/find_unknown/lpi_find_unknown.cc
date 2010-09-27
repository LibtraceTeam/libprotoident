/* Example program using libflowmanager to count flows in a trace file. 
 * Demonstrates how the libflowmanager API should be used to perform flow-based
 * measurements.
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
bool only_dir1 = true;


/* This data structure is used to demonstrate how to use the 'extension' 
 * pointer to store custom data for a flow */
typedef struct unknown {
	uint8_t init_dir;
	lpi_data_t lpi;
} UnknownFlow;

/* Initialises the custom data for the given flow. Allocates memory for a
 * UnknownFlow structure and ensures that the extension pointer points at
 * it.
 */
void init_counter_flow(Flow *f, uint8_t dir) {
	UnknownFlow *unk = NULL;

	unk = (UnknownFlow *)malloc(sizeof(UnknownFlow));
	unk->init_dir = dir;
	lpi_init_data(&unk->lpi);
	f->extension = unk;
}

void display_unknown(Flow *f, UnknownFlow *unk) {

        char ip[50];
        char str[1000];
        struct in_addr in;

	if (only_dir0 && unk->init_dir == 1)
		return;
	if (only_dir1 && unk->init_dir == 0)
		return;


        in.s_addr = f->id.get_server_ip();
        snprintf(ip, 1000, "%s", inet_ntoa(in));

        in.s_addr = f->id.get_client_ip();
        snprintf(str, 1000, "%s %s %u %u %u %u    ", ip, inet_ntoa(in),
                        f->id.get_server_port(), f->id.get_client_port(),
                        f->id.get_id_num(), f->id.get_protocol());

	printf("%s %08x,%08x\n", str, ntohl(unk->lpi.payload[0]),
			ntohl(unk->lpi.payload[1]));	

}

/* Expires all flows that libflowmanager believes have been idle for too
 * long. The exp_flag variable tells libflowmanager whether it should force
 * expiry of all flows (e.g. if you have reached the end of the program and
 * want the stats for all the still-active flows). Otherwise, only flows
 * that have been idle for longer than their expiry timeout will be expired.
 */
void expire_counter_flows(double ts, bool exp_flag) {
        Flow *expired;
	lpi_protocol_t proto;

        /* Loop until libflowmanager has no more expired flows available */
	while ((expired = lfm_expire_next_flow(ts, exp_flag)) != NULL) {

                UnknownFlow *unk = (UnknownFlow *)expired->extension;
		
		proto = lpi_guess_protocol(&unk->lpi);
		if (proto == LPI_PROTO_UNKNOWN || proto == LPI_PROTO_UDP)
			display_unknown(expired, unk);
		

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
        libtrace_ip_t *ip = NULL;
        double ts;

        uint16_t l3_type;

        /* Libflowmanager only deals with IP traffic, so ignore anything
	 * that does not have an IP header */
        ip = (libtrace_ip_t *)trace_get_layer3(packet, &l3_type, NULL);
        if (l3_type != 0x0800) return;
        if (ip == NULL) return;


	/* Many trace formats do not support direction tagging (e.g. PCAP), so
	 * using trace_get_direction() is not an ideal approach. The one we
	 * use here is not the nicest, but it is pretty consistent and 
	 * reliable. Feel free to replace this with something more suitable
	 * for your own needs!.
	 */
	dir = trace_get_direction(packet);

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
        if (f == NULL)
                return;

	/* If the returned flow is new, you will probably want to allocate and
	 * initialise any custom data that you intend to track for the flow */
        if (is_new)
                init_counter_flow(f, dir);
	
	/* Cast the extension pointer to match the custom data type */	
        unk = (UnknownFlow *)f->extension;
	lpi_update_data(packet, &unk->lpi, dir);

        /* Update TCP state for TCP flows. The TCP state determines how long
	 * the flow can be idle before being expired by libflowmanager. For
	 * instance, flows for which we have only seen a SYN will expire much
	 * quicker than a TCP connection that has completed the handshake */
        tcp = trace_get_tcp(packet);
        ts = trace_get_seconds(packet);
        if (tcp) {
                lfm_check_tcp_flags(f, tcp, dir, ts);
        }

        /* Tell libflowmanager to update the expiry time for this flow */
        lfm_update_flow_expiry_timeout(f, ts);

	/* Expire all suitably idle flows */
        expire_counter_flows(ts, false);

}


int main(int argc, char *argv[]) {

        libtrace_t *trace;
        libtrace_packet_t *packet;

        bool opt_true = true;
        bool opt_false = false;

        int i;
        double ts;

        packet = trace_create_packet();
        if (packet == NULL) {
                perror("Creating libtrace packet");
                return -1;
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

        optind = 1;

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
        expire_counter_flows(ts, true);

        return 0;

}

