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

/* The basis of this code was taken from the lpi_live tool and moved into a
 * separate source file that could be shared between the original tool and our
 * new collector.
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
#include <errno.h>
#include <sys/types.h>
#include <netdb.h>
#include <map>

#include <libflowmanager.h>
#include <libtrace.h>
#include <libwandevent.h>

#include "live_common.h"

/* These macros should make this code a lot more readable */
#define PROTONUM (live->proto->protocol)
#define OUT_BYTES (cnt->out_byte_count)
#define IN_BYTES (cnt->in_byte_count)
#define OUT_PKTS (cnt->out_pkt_count)
#define IN_PKTS (cnt->in_pkt_count)
#define OUT_NEW (cnt->out_flow_count)
#define IN_NEW (cnt->in_flow_count)
#define OUT_CURR (cnt->out_current_flows)
#define IN_CURR (cnt->in_current_flows)
#define OUT_PEAK (cnt->out_peak_flows)
#define IN_PEAK (cnt->in_peak_flows)


static inline IPCollector * create_ip_collector() {
	IPCollector *col = NULL;

	col = (IPCollector *)malloc(sizeof(IPCollector));
	memset(col->currently_active_flows, 0, LPI_PROTO_LAST * sizeof(uint64_t));
	memset(col->total_observed_period, 0, LPI_PROTO_LAST * sizeof(uint64_t));

	return col;
}


static void wipe_local_ip_collectors(IPMap *ipmap) {
	
	IPMap::iterator ii = ipmap->begin();

	while (ii != ipmap->end()) {
		IPMap::iterator tmp = ii;
		ii ++;
		free(tmp->second);
		ipmap->erase(tmp);
	}

	assert(ipmap->empty());
}

static void reset_local_ip_counts(uint64_t *counts, IPMap *ipmap) {

	IPMap::iterator ii = ipmap->begin();

	while (ii != ipmap->end()) {
		bool active = false;

		for (int i = 0; i < LPI_PROTO_LAST; i++) {
			ii->second->total_observed_period[i] = 
				ii->second->currently_active_flows[i];
			if (ii->second->total_observed_period[i] > 0) {
				counts[i]++;
				active = true;
			}
		}

		if (!active) {
			/* If there are no active flows for this IP,
			 * remove it from the IP map to save space
			 */
			IPMap::iterator tmp = ii;
			ii ++;
			free((char *)tmp->first);
			free(tmp->second);
			ipmap->erase(tmp);
		} else {
			ii++;
		}
	}

}

static int reset_user(UserCounters *user, bool wipe_all) {
	size_t array_size = LPI_PROTO_LAST * sizeof(uint64_t);

	memset(user->in_pkt_count, 0, array_size);
        memset(user->out_pkt_count, 0, array_size);
        memset(user->in_byte_count, 0, array_size);
        memset(user->out_byte_count, 0, array_size);
        memset(user->in_flow_count, 0, array_size);
        memset(user->out_flow_count, 0, array_size);
        
        memset(user->remote_ips, 0, array_size);
                
        /* Don't reset the current flow count unless told to! */
        if (wipe_all) {
                memset(user->in_current_flows, 0, array_size);
                memset(user->out_current_flows, 0, array_size);
        } 
	
        for (int i = 0; i < LPI_PROTO_LAST; i++) {
                user->in_peak_flows[i] = user->in_current_flows[i];
                user->out_peak_flows[i] = user->out_current_flows[i];
        }


	if (user->in_current_flows > 0)
		return 0;
	if (user->out_current_flows > 0)
		return 0;

	/* Tell the caller that this user is no longer active and can be
	 * released */
	return 1;

}

void reset_counters(LiveCounters *cnt, bool wipe_all) {

	UserMap::iterator it, tmp; 

	reset_user(&cnt->all, wipe_all);

	it = cnt->users.begin();

	while (it != cnt->users.end()) {
		if (reset_user(it->second, wipe_all)) {
			tmp = it;
			it ++;
			free((void *)tmp->first);
			free(tmp->second);
			cnt->users.erase(tmp);
		} else {
			it ++;
		}
	}
        memset(cnt->all_local_ips, 0, LPI_PROTO_LAST * sizeof(uint64_t));
        memset(cnt->active_local_ips, 0, LPI_PROTO_LAST * sizeof(uint64_t));

	if (!wipe_all) {
		reset_local_ip_counts(cnt->all_local_ips, &cnt->observed_local);
		reset_local_ip_counts(cnt->active_local_ips, &cnt->active_local);
	} else {
		wipe_local_ip_collectors(&cnt->observed_local);
		wipe_local_ip_collectors(&cnt->active_local);
	}
	cnt->reports ++;
}


void init_live_counters(LiveCounters *cnt, bool track_users) {

	cnt->user_tracking = track_users;
	reset_counters(cnt, true);
	
	/* Force the report count to be zero, because reset_counters would
	 * normally increment it */
	cnt->reports = 0;
}

void init_live_flow(LiveCounters *cnt, Flow *f, uint8_t dir, double ts) {
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
        live->start_period = cnt->reports;
        live->count_period = cnt->reports;
        lpi_init_data(&live->lpi);
        f->extension = live;
        live->proto = NULL;

	live->activated_ip = false;

        f->id.get_local_ip_str(live->local_ip);
        f->id.get_external_ip_str(live->ext_ip);

	if (cnt->user_tracking) {
		/* Create a new counter for the user if needed */
		UserMap::iterator it = cnt->users.find(live->local_ip);
		if (it != cnt->users.end())
			return;

		size_t key_len = strlen(live->local_ip) + 1;
		char *key = (char *)malloc(key_len);
		memcpy(key, live->local_ip, key_len);
		
		UserCounters *uc = (UserCounters *)malloc(sizeof(UserCounters));
		reset_user(uc, true);
		cnt->users[key] = uc;
		cnt->user_count ++;
	}


}

static void stdout_counter_array(double ts, const char *id, uint32_t freq,
                const char *type, uint64_t *counter) {

        int i;


        for (i = 0; i < LPI_PROTO_LAST; i++) {
		/* Ignore protocols that are deprecated in libprotoident */
                if (lpi_is_protocol_inactive((lpi_protocol_t)i))
                        continue;

                fprintf(stdout, "%s,%.0f,%u,%s,%s,", id, ts, freq, type,
                                lpi_print((lpi_protocol_t)i));
                fprintf(stdout, "%" PRIu64 "\n", counter[i]);
        }

}

/* Dumps the values for all of our counters to standard output */
void dump_counters_stdout(UserCounters *cnt, double ts, char *local_id, 
		uint32_t report_freq) {

        stdout_counter_array(ts, local_id, report_freq, "in_pkts", IN_PKTS);
        stdout_counter_array(ts, local_id, report_freq, "out_pkts", OUT_PKTS);
        stdout_counter_array(ts, local_id, report_freq, "in_bytes", IN_BYTES);
        stdout_counter_array(ts, local_id, report_freq, "out_bytes", OUT_BYTES);
        stdout_counter_array(ts, local_id, report_freq, "in_new_flows", IN_NEW);
        stdout_counter_array(ts, local_id, report_freq, "out_new_flows", OUT_NEW);
        stdout_counter_array(ts, local_id, report_freq, "in_peak_flows", IN_PEAK);
        stdout_counter_array(ts, local_id, report_freq, "out_peak_flows", OUT_PEAK);

}

/* Safely decrements a counter value - this way we won't reduce below zero and
 * succumb to integer wrapping bugs */
static inline void decrement_counter(uint64_t *array, lpi_protocol_t proto,
                uint32_t val) {

        if (array[proto] < val) {
                array[proto] = 0;
        }
        else {
                array[proto] -= val;
        }

}

/* Determines whether it is worth calling lpi_guess_protocol for a flow */
static bool should_guess(LiveFlow *live, uint32_t plen, uint8_t dir) {

	/* Special case to deal with possible "No Payload" flows */
        if (live->out_pbytes == 0 && live->in_pbytes == 0 && live->proto == NULL)
                return true;

	/* If the current packet has no payload, then it is not going to
 	 * change anything */
        if (plen == 0)
                return false;

	/* If this is the first outgoing packet with payload, check */ 
        if (dir == 0 && live->out_pbytes == plen)
                return true;
	/* If this is the first incoming packet with payload, check */
        if (dir == 1 && live->in_pbytes == plen)
                return true;

	/* This is a payload bearing packet but it isn't the first for that
	 * direction so it isn't going to affect libprotoident at all */
        return false;
}

static inline void activate_local_ip(LiveFlow *live, IPMap *ipmap, 
		uint64_t *ip_counts) {

	/* Update the IP map for this flow */
	IPMap::iterator it;
	IPCollector *ip_coll = NULL;

	it = ipmap->find(live->local_ip);
	if (it == ipmap->end()) {
		size_t key_len = strlen(live->local_ip) + 1;
		char *key = (char *)malloc(key_len);
		memcpy(key, live->local_ip, key_len);
		
		ip_coll = create_ip_collector();
		(*ipmap)[key] = ip_coll;

	} else {
		ip_coll = it->second;
	}

	ip_coll->currently_active_flows[PROTONUM] += 1;
	ip_coll->total_observed_period[PROTONUM] += 1;

	if (ip_coll->total_observed_period[PROTONUM] == 1)
		ip_counts[PROTONUM] += 1;	

}

static inline void swap_local_ip(LiveFlow *live, IPMap *ipmap, 
		uint64_t *ip_counts, lpi_protocol_t old) {

	IPCollector *col = NULL;
	IPMap::iterator it = ipmap->find(live->local_ip);
	assert(it != ipmap->end());

	col = it->second;
	assert(col->currently_active_flows[old] > 0);
	assert(col->total_observed_period[old] > 0);

	col->currently_active_flows[old] -= 1;
	col->total_observed_period[old] -= 1;
	col->currently_active_flows[PROTONUM] += 1;
	col->total_observed_period[PROTONUM] += 1;

	if (col->total_observed_period[old] == 0) {
		ip_counts[old] -= 1;
	}
	if (col->total_observed_period[PROTONUM] == 1) {
		ip_counts[PROTONUM] += 1;
	}
	
	
}

static inline void deactivate_local_ip(LiveFlow *live, IPMap *ipmap) { 

	IPMap::iterator it = ipmap->find(live->local_ip);
	assert(it != ipmap->end());
	IPCollector *col = it->second;
	col->currently_active_flows[PROTONUM] -= 1;

}

static inline void update_unchanged(LiveFlow *live, UserCounters *cnt,
                uint32_t wlen,  uint8_t dir) {
        /* The protocol classification hasn't changed, so just increment
	 * the packet and byte counters based on the new packet */

	if (dir == 0) {
                OUT_BYTES[PROTONUM] += wlen;
                OUT_PKTS[PROTONUM] += 1;
        } else {
                IN_BYTES[PROTONUM] += wlen;
                IN_PKTS[PROTONUM] += 1;
        }
}

static inline void update_unchanged_ip(LiveFlow *live, LiveCounters *cnt,
		uint32_t plen, uint8_t dir) {

	/* Basically, we are just checking for cases where the flow has not
	 * seen any outgoing payload originally, but this last packet has
	 * changed that so we need to count the local IP as active */

	if (dir != 0)
		return;
	if (plen == 0)
		return;
	if (plen != live->out_pbytes)
		return;

	if (PROTONUM == LPI_PROTO_NO_PAYLOAD)
		assert(0);
	assert(live->activated_ip == false);
	//printf("UNCHANGED: Activating %s\n", live->local_ip, PROTONUM);	
	activate_local_ip(live, &(cnt->active_local), cnt->active_local_ips);
	live->activated_ip = true;
}

static inline void update_new(LiveFlow *live, UserCounters *cnt) {

	/* This is a new flow that has been classified for the first
	 * time. We therefore need to increase the new, current and
	 * possibly peak flow counters for whatever protocol we belong
	 * to */
        if (live->init_dir == 0) {
                OUT_NEW[PROTONUM] += 1;
                OUT_CURR[PROTONUM] += 1;

                if (OUT_CURR[PROTONUM] > OUT_PEAK[PROTONUM])
                        OUT_PEAK[PROTONUM] = OUT_CURR[PROTONUM];
        } else {
                IN_NEW[PROTONUM] += 1;
                IN_CURR[PROTONUM] += 1;

                if (IN_CURR[PROTONUM] > IN_PEAK[PROTONUM])
                        IN_PEAK[PROTONUM] = IN_CURR[PROTONUM];

        }

	/* Also add our packet and byte counts to the appropriate counters */
	OUT_BYTES[PROTONUM] += live->out_wbytes;
	OUT_PKTS[PROTONUM] += live->out_pkts;
	IN_BYTES[PROTONUM] += live->in_wbytes;
	IN_PKTS[PROTONUM] += live->in_pkts;
	
}

static inline void update_new_ip(LiveFlow *live, LiveCounters *cnt) {

	/* New flow, so increment the observed IP count */
	activate_local_ip(live, &(cnt->observed_local), cnt->all_local_ips);

	/* If this flow has sent payload in direction 0, update the active
	 * IP count too */

	if (live->out_pbytes == 0) {
		return;
	}

	if (PROTONUM == LPI_PROTO_NO_PAYLOAD)
		assert(0);

	//printf("NEW: Activating %s %d\n", live->local_ip, PROTONUM);	
	assert(live->activated_ip == false);
	activate_local_ip(live, &(cnt->active_local), cnt->active_local_ips);
	live->activated_ip = true;
}


static inline void update_changed(LiveFlow *live, UserCounters *cnt, 
		uint32_t wlen, uint8_t dir, uint32_t period,
		lpi_protocol_t old) {

	/* Protocol has "changed" - subtract whatever we would have
	 * inserted into the previous protocol counter and shift those
	 * values into the new one */
	
	/* If the current period is the same period as when the flow
	 * started, we need to correct our new flow counter */
	if (period == live->start_period) {

		if (live->init_dir == 0) {
			assert(OUT_NEW[old] > 0);
			OUT_NEW[old] --;
			OUT_NEW[PROTONUM] ++;
		} else {
			assert(IN_NEW[old] > 0);
			IN_NEW[old] --;
			IN_NEW[PROTONUM] ++;
		}
	}

	/* Update the current and peak flow counts as necessary. Peak flow
	 * counts can end up being a bit misleading as a result - you can't
	 * really do it live AND get complete accuracy :/ */

	if (live->init_dir == 0) {
		assert(OUT_CURR[old] > 0);
		OUT_CURR[old] --;
		OUT_CURR[PROTONUM] ++;
                if (OUT_CURR[PROTONUM] > OUT_PEAK[PROTONUM])
                        OUT_PEAK[PROTONUM] = OUT_CURR[PROTONUM];
	} else {
		assert(IN_CURR[old] > 0);
		IN_CURR[old] --;
		IN_CURR[PROTONUM] ++;
                if (IN_CURR[PROTONUM] > IN_PEAK[PROTONUM])
                        IN_PEAK[PROTONUM] = IN_CURR[PROTONUM];
	}

	/* The stats in the LiveFlow include the current packet, but the
	 * current counter values do not so we need to NOT include the current
	 * packet when correcting the byte and packet counts */

	if (dir == 0) {

		assert(live->out_wbytes >= wlen);
		assert(live->out_pkts >= 1);
		decrement_counter(IN_BYTES, old, live->in_wbytes);
		decrement_counter(IN_PKTS, old, live->in_pkts);
		decrement_counter(OUT_BYTES, old, live->out_wbytes - wlen);
		decrement_counter(OUT_PKTS, old, live->out_pkts - 1);

	} else {
		assert(live->in_wbytes >= wlen);
		assert(live->in_pkts >= 1);
		decrement_counter(OUT_BYTES, old, live->out_wbytes);
		decrement_counter(OUT_PKTS, old, live->out_pkts);
		decrement_counter(IN_BYTES, old, live->in_wbytes - wlen);
		decrement_counter(IN_PKTS, old, live->in_pkts - 1);

	}
	/* Right, now we can add our packets and bytes to the counter for
	 * our new protocol */
	OUT_BYTES[PROTONUM] += live->out_wbytes;
	OUT_PKTS[PROTONUM] += live->out_pkts;
	IN_BYTES[PROTONUM] += live->in_wbytes;
	IN_PKTS[PROTONUM] += live->in_pkts;
}

static void update_changed_ip(LiveFlow *live, LiveCounters *cnt, 
		uint32_t plen, uint8_t dir, lpi_protocol_t old) {
	
	swap_local_ip(live, &cnt->observed_local, cnt->all_local_ips, old);

	if (live->out_pbytes == 0)
		return;
	
	if (PROTONUM == LPI_PROTO_NO_PAYLOAD)
		assert(0);
	if (dir == 0 && plen == live->out_pbytes) {
		/* The packet that triggered the change is the first 
		 * outgoing packet for this flow, so we haven't activated
		 * the IP for this flow yet! */
		//printf("SWAP: Activating %s %d\n", live->local_ip, PROTONUM);	
		activate_local_ip(live, &(cnt->active_local), 
				cnt->active_local_ips);
		return;
	}
	
	//printf("Swapping %s %d->%d\n", live->local_ip, old, PROTONUM);	
	swap_local_ip(live, &cnt->active_local, cnt->active_local_ips, old);
}
	

int update_protocol_counters(LiveFlow *live, LiveCounters *cnt, uint32_t wlen,
                uint32_t plen, uint8_t dir) {

	/* Remember the old protocol before we overwrite it! */
	lpi_module_t *old_proto = live->proto;

	/* We only want to ask lpi for the protocol if there is a chance that
	 * the protocol may have changed. */
        if (should_guess(live, plen, dir)) {
                live->proto = lpi_guess_protocol(&live->lpi);
        }

        if (live->proto == NULL) {
                fprintf(stderr, "Warning: guessed NULL protocol\n");
                return -1;
        }

        if (old_proto == live->proto) {
                update_unchanged(live, &cnt->all, wlen, dir);
		if (cnt->user_tracking) {
			update_unchanged(live, cnt->users[live->local_ip],
					wlen, dir);
		}
		update_unchanged_ip(live, cnt, plen, dir);
        } else if (old_proto == NULL) {
                update_new(live, &cnt->all);
		if (cnt->user_tracking) {
			update_new(live, cnt->users[live->local_ip]);
		}
		update_new_ip(live, cnt);

        } else {
		update_changed(live, &cnt->all, wlen, dir, cnt->reports, 
				old_proto->protocol);
		if (cnt->user_tracking) {
			update_changed(live, cnt->users[live->local_ip],
					wlen, dir, cnt->reports, 
					old_proto->protocol);
		}
		update_changed_ip(live, cnt, plen, dir, old_proto->protocol);
	}

	return 0;
}

void update_liveflow_stats(LiveFlow *live, libtrace_packet_t *packet,
		LiveCounters *cnt, uint8_t dir) {

	/* We're in a new reporting period - reset our stats because we
 	 * only want the amount of traffic since we last reported */
	if (live->count_period != cnt->reports) {
                live->out_wbytes = 0;
                live->out_pkts = 0;
                live->in_wbytes = 0;
                live->in_pkts = 0;
                live->count_period = cnt->reports;
        }
        
	assert(trace_get_payload_length(packet) <= 65536);

        if (dir == 0) {
                live->out_pbytes += trace_get_payload_length(packet);
                live->out_wbytes += trace_get_wire_length(packet);
                live->out_pkts += 1;
        } else {
                live->in_pbytes += trace_get_payload_length(packet);
                live->in_wbytes += trace_get_wire_length(packet);
                live->in_pkts += 1;

        }

}

static inline void update_counter_expired(LiveFlow *live, UserCounters *cnt) {
	if (live->init_dir == 0) {
		assert(OUT_CURR[PROTONUM] != 0);
		OUT_CURR[PROTONUM] --;
	} else {
		assert(IN_CURR[PROTONUM] != 0);
		IN_CURR[PROTONUM] --;
	}
}

static inline void update_expired_ip(LiveFlow *live, LiveCounters *cnt) {

	deactivate_local_ip(live, &(cnt->observed_local));
	if (live->out_pbytes == 0)
		return;
	deactivate_local_ip(live, &(cnt->active_local));

}

void destroy_live_flow(LiveFlow *live, LiveCounters *cnt) {

	/* Decrement the currently active flow counter for our matching
	 * protocol */
	
	update_counter_expired(live, &cnt->all);
	if (cnt->user_tracking) {
		update_counter_expired(live, cnt->users[live->local_ip]);
	}
	
	update_expired_ip(live, cnt);
	free(live);
}


