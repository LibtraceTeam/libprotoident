/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2012 The University of Waikato, Hamilton, New Zealand.
 * Author: Meenakshee Mungro
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
 * $Id: lpi_live.cc 135 2012-11-29 04:01:59Z salcock $
 */


#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <libtrace.h>
#include <libwandevent.h>
#include <libflowmanager.h>
#include <libprotoident.h>
#include <libpacketdump.h>

#include "../tools_common.h"
#include "live_common.h"

wand_event_handler_t *ev_hdl = NULL;

enum {
        DIR_METHOD_TRACE,
        DIR_METHOD_MAC,
        DIR_METHOD_PORT
};

int dir_method = DIR_METHOD_TRACE;

char *local_mac = NULL;
uint8_t mac_bytes[6];

libtrace_t *trace = NULL;
libtrace_packet_t *packet = NULL;

/* Number of seconds that have passed since the counters were last reset */
uint32_t report_freq = 300;

/* String that identifies this particular measurement process */ 
char *local_id = (char*) "unnamed";

/* A file descriptor event - used when waiting on input from a live interface */
struct wand_fdcb_t fd_cb;
/* A timer event - used when waiting for the next packet to occur in a trace 
 * file replay
 */
struct wand_timer_t packet_timer;
/* Timer that fires every n seconds, where n is the interval at which output is 
 * produced 
 */
struct wand_timer_t output_timer;
/* Signal event which is triggered when the user triggers a SIGINT */
struct wand_signal_t signal_sigint;
/* Struct that stores the time at which the reporting period started */
struct timeval start_reporting_period;

static volatile int done = 0;

LiveCounters counts;

/* Function prototype */
void collect_packets(libtrace_t *trace, libtrace_packet_t *packet );

void usage(char *prog) {
	return;
}

/* Function which prints the stats to the console every n seconds, where n is a 
 * value provided in the command line arguments 
 */
void output_stats(struct wand_timer_t *timer)
{
	struct timeval *tv;
	tv = (struct timeval *) timer->data;	
	
	output_timer.expire = wand_calc_expire(ev_hdl, report_freq, 0);
	output_timer.callback = output_stats;	
	gettimeofday(&start_reporting_period, NULL);	
	output_timer.data = &start_reporting_period;

	/* the timer will be inserted into a doubly linked list and pointers 
	 * should start out as NULL */
	output_timer.prev = output_timer.next = NULL;

	wand_add_timer(ev_hdl, &output_timer);

	/* Call method which will dump the values of all the counters to 
	 * standard output */
	dump_counters_stdout(&counts, tv->tv_sec, local_id, report_freq);
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
		destroy_live_flow(live, &counts);
		
		/* VERY IMPORTANT: delete the Flow structure itself, even
		 * though we did not directly allocate the memory ourselves 
		 */
		lfm_release_flow(expired);
	}
}

/* Function which processes a packet after it is read from the trace.
 * It expires any old flows that are due to expire, takes the current packet 
 * and matches it to the flow it belongs to, checks if it is a new flow and acts
 * accordingly, updates the state properly by checking if it is a TCP flow, and
 * updates the expiry time for the current flow. 
 */
void process_packet(libtrace_packet_t *packet)
{
	uint8_t dir = 255;
	Flow *f;
	LiveFlow *live = NULL;
	bool is_new = false;
    
	/* Defines a tcp header structure */
	libtrace_tcp_t *tcp = NULL;
	void *l3;
	double ts;

	uint16_t l3_type = 0;

	l3 = trace_get_layer3(packet, &l3_type, NULL);
	/* if the packet is not an IPv4 or IPv6 packet */
	if (l3_type != TRACE_ETHERTYPE_IP && l3_type != TRACE_ETHERTYPE_IPV6) 
		return;
	if (l3 == NULL) 
		return;
    
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
	 * is_new flag to true */
	f = lfm_match_packet_to_flow(packet, dir, &is_new);

	/* Libflowmanager did not like something about that packet - best to
	 * just ignore it and carry on */
	if (f == NULL) {
		return;
	}
	    
	tcp = trace_get_tcp(packet);
	
	/* If the returned flow is new, allocate and initialise any custom data 
	 * that needs to be tracked for the flow */
	if (is_new) {	
		init_live_flow(&counts, f, dir, ts);
		live = (LiveFlow *)f->extension;
	} 
	else {
		live = (LiveFlow *)f->extension;
	}
	
	/* Call method which updates the statistics stored in the LiveFlow 
         * structure, based on the provided packet */
	update_liveflow_stats(live, packet, &counts, dir);
	
	/* Pass the packet into libprotolive so that it can extract any
	 * info it needs from this packet */
	lpi_update_data(packet, &live->lpi, dir);	
	
	if (update_protocol_counters( live, &counts, 
				trace_get_wire_length(packet),
				trace_get_payload_length(packet), dir) == -1) {		
		trace_dump_packet(packet);	
	}
		
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

/* File descriptor callback method which is executed when a fd is added */
void source_read_event( struct wand_fdcb_t *event, 
			enum wand_eventtype_t event_type)
{
	wand_del_event(ev_hdl, event);

	/* Not very nice if this fails but it really REALLY shouldn't fail */
	assert(event_type == EV_READ);
	collect_packets(trace, packet);
}

/* Callback function for packet_timer which is executed when the timer fires */
void sleep_timer_event(struct wand_timer_t *timer)
{
	collect_packets(trace, packet);
}

/* Function which handles a SIGINT by deleting the signal and halting execution
 * of the program
 */
static void cleanup_signal(struct wand_signal_t *signal ) 
{	
	wand_del_signal(signal);
		
	fprintf(stdout, "%s\n", "Terminating program...");
	done = 1;
	ev_hdl->running = false;
}

/* Function which processes a libtrace event and executes the appropriate code 
 * for each event type
 */
int process_event(libtrace_eventobj_t event, libtrace_packet_t *packet)
{
	switch(event.type)
	{
		/* wait on a file descriptor(comes up when working with a live 
		 * source) */
		case TRACE_EVENT_IOWAIT:
			fd_cb.fd = event.fd;
			/* only catering to READ events */
			fd_cb.flags = EV_READ;
			fd_cb.data = NULL;
			fd_cb.callback = source_read_event;
			wand_add_event(ev_hdl, &fd_cb);
			/* Stop the current poll loop */
			return 0;
		
		/* this event type comes up with static trace files */
		case TRACE_EVENT_SLEEP:
			/* Next packet will be available in N seconds, sleep 
			 * until then */
			int micros;
			micros = (int)((event.seconds - 
					(int)event.seconds) * 1000000.0);
			packet_timer.expire = wand_calc_expire(ev_hdl, 
						(int)event.seconds, micros);
			
			packet_timer.callback = sleep_timer_event;
			packet_timer.data = NULL;
			/* the timer will be inserted into a doubly linked list 
			 * and pointers should start out as NULL */
			packet_timer.prev = packet_timer.next = NULL;

			wand_add_timer(ev_hdl, &packet_timer);
			return 0;
			
		case TRACE_EVENT_PACKET:
			/* A packet is available - pass it on to the meter */
			if (event.size == -1)
			{
				/* Error occured */
				/* We don't need wdcap's fancy error handling - 
				 * just drop the trace */
				ev_hdl->running = false;
				return 0;
			}

			/* No error, so call function which processes packets */
			process_packet(packet);

			/* check for more packets */
			return 1;
			
		case TRACE_EVENT_TERMINATE:
			/* The input trace has terminated */
			ev_hdl->running = false;
			return 0;
		
		default:
			fprintf(stderr, "Unknown libtrace event type: %d\n", 
						event.type);
			return 0;	
	}	
}

/* Function which polls the trace for the next packet if available */
void collect_packets(libtrace_t *trace, libtrace_packet_t *packet )
{
	struct libtrace_eventobj_t event;
	int poll_again = 1;

	do
	{
		if (done)
			return;
			
		/* Process the next libtrace event from an input trace and 
		 * return a libtrace_event struct containing the event type and 
		 * details of the event */
		event = trace_event(trace, packet);

		/* process_event returns 1(allows resuming packet checking) or
		 *  0(stops polling) */
		poll_again = process_event(event, packet);		
	}
	
	while (poll_again);	
}

int main(int argc, char *argv[])
{
	int opt, i;
	libtrace_filter_t *filter = NULL;
	char *filterstring = NULL;
	
	bool opt_false = false;
	bool ignore_rfc1918 = false;
	
	/* Initialise libwandevent */
	if (wand_event_init() == -1) {
		fprintf(stderr, "Error initialising libwandevent\n");
		return -1;
	}
	
	/* create an event handler */
	ev_hdl = wand_create_event_handler();
		
	if (ev_hdl == NULL) {
		fprintf(stderr, "Error creating event handler\n");
		return -1;
	}
	
	/* event handler has been correctly created, so add a signal event */
	signal_sigint.signum = SIGINT;
	signal_sigint.data = NULL;
	signal_sigint.callback = cleanup_signal;
	wand_add_signal(&signal_sigint);	
	
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	while ((opt = getopt(argc, argv, "f:l:i:r:TPR")) != EOF) {
		switch (opt) {
			/* Ignore flows that do not match the given BPF filter */
			case 'f':
				filterstring = optarg;
				break;
			/* Determine direction based on <mac> representing the 
			 * 'inside' portion of the network */
			case 'l':
				local_mac = optarg;
				dir_method = DIR_METHOD_MAC;
				break;
			/* Store string that will identify this particular 
			 * measurement process, e.g. source of the packets   */
			case 'i':
				local_id = optarg;
				break;
			/* Store the number of seconds that have passed since 
			 * the counters were last reset */
			case 'r':
				report_freq = atoi(optarg);
				break;
			/* Use trace direction tags to determine direction */
			case 'T':
				dir_method = DIR_METHOD_TRACE;
				break;
			/* Use port number to determine direction */
			case 'P':
				dir_method = DIR_METHOD_PORT;
				break;
			/* ignore any flows where an RFC1918 private IP address 
			 * is involved */ 
			case 'R':
				ignore_rfc1918 = true;
				break;

			default:
				usage(argv[0]);
		}
	}

	// if -l <mac> was specified in the command line args
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

	/* This tells libflowmanager not to replicate the TCP timewait behaviour 
	 * where closed TCP connections are retained in the Flow map for an 
	 * extra 2 minutes */
	if (lfm_set_config_option(LFM_CONFIG_TCP_TIMEWAIT, &opt_false) == 0)
		return -1;

	/* This tells libflowmanager not to utilise the fast expiry rules for 
	 * short-lived UDP connections - these rules are experimental behaviour 
	 * not in line with recommended "best" practice */
	if (lfm_set_config_option(LFM_CONFIG_SHORT_UDP, &opt_false) == 0)
		return -1;

	if (optind + 1 > argc) {
		usage(argv[0]);
		return 1;
	}
	
	if (lpi_init_library() == -1)
		return -1;
	
	/* nothing has gone wrong yet, so create packet */
	packet = trace_create_packet();

	if (filterstring) {
		filter = trace_create_filter(filterstring);
	}

	output_timer.expire = wand_calc_expire(ev_hdl, report_freq, 0);
	output_timer.callback = output_stats;
	gettimeofday(&start_reporting_period, NULL);	
	output_timer.data = &start_reporting_period;
	output_timer.prev = output_timer.next = NULL ;
	wand_add_timer(ev_hdl, &output_timer);
	
	for (i = optind; i < argc; i++) {
		/* Create an input trace from a URI provided in arguments and 
		 * return a pointer to a libtrace_t */
		trace = trace_create(argv[i]);

		if (trace_is_err(trace)) {
			/* outputs the error message for an input trace to 
			 * stderr and clear the error status. */
			trace_perror(trace,"Opening trace file");
			return 1;
		}

		if (filter && trace_config(trace, TRACE_OPTION_FILTER, 
								filter) == -1) {
			trace_perror(trace, "trace_config(filter)");
			return 1;
		}

		// Start an input trace and returns 0 on success, -1 on failure
		if (trace_start(trace)) {
			trace_perror(trace,"Starting trace");
			trace_destroy(trace);
			return 1;
		}

		/* as long as this is true, libwandevent will keep running */
		ev_hdl->running = true;
		
		collect_packets(trace, packet);
		
		/* Once we hit a wait event, fire up the event handler. We
		 * won't fall out of this function call until we reach the
		 * end of the trace or something goes awry with reading
		 * the trace */
		wand_event_run(ev_hdl);

		/* if there's an error after the event handler has started */
		if (trace_is_err(trace)) {
			trace_perror(trace,"Reading packets");
			trace_destroy(trace);
			return 1;
		}
		
		if (done)
			break;
		
		/* Close an input trace, freeing up any resources it may have 
		 * been using */
		trace_destroy(trace);
	}
	
	/* cleaning up resources and final exporting of flows */
	if (filter)
		trace_destroy_filter(filter);

	trace_destroy_packet(packet);
	wand_destroy_event_handler(ev_hdl);
	expire_live_flows(0, true);
	lpi_free_library();
	
	return 0;
}
