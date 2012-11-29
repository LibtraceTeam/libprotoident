#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include <libflowmanager.h>
#include <libtrace.h>

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

        f->id.get_local_ip_str(live->local_ip);
        f->id.get_external_ip_str(live->ext_ip);
}

void reset_counters(LiveCounters *cnt, bool wipe_all) {
        memset(cnt->in_pkt_count, 0, LPI_PROTO_LAST * sizeof(uint64_t));
        memset(cnt->out_pkt_count, 0, LPI_PROTO_LAST * sizeof(uint64_t));
        memset(cnt->in_byte_count, 0, LPI_PROTO_LAST * sizeof(uint64_t));
        memset(cnt->out_byte_count, 0, LPI_PROTO_LAST * sizeof(uint64_t));
        memset(cnt->in_flow_count, 0, LPI_PROTO_LAST * sizeof(uint64_t));
        memset(cnt->out_flow_count, 0, LPI_PROTO_LAST * sizeof(uint64_t));

        /* Don't reset the current flow count unless told to! */
        if (wipe_all) {
                memset(IN_CURR, 0, LPI_PROTO_LAST*sizeof(uint64_t));
                memset(OUT_CURR, 0, LPI_PROTO_LAST*sizeof(uint64_t));
        }
        for (int i = 0; i < LPI_PROTO_LAST; i++) {
                cnt->in_peak_flows[i] = cnt->in_current_flows[i];
                cnt->out_peak_flows[i] = cnt->out_current_flows[i];
        }


	cnt->reports ++;

}

void init_live_counters(LiveCounters *cnt) {

	reset_counters(cnt, true);
	
	/* Force the report count to be zero, because reset_counters would
	 * normally increment it */
	cnt->reports = 0;
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
void dump_counters_stdout(LiveCounters *cnt, double ts, char *local_id, 
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


static inline void update_unchanged(LiveFlow *live, LiveCounters *cnt,
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

static inline void update_new(LiveFlow *live, LiveCounters *cnt) {

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


static inline void update_changed(LiveFlow *live, LiveCounters *cnt, 
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
                update_unchanged(live, cnt, wlen, dir);
        } else if (old_proto == NULL) {
                update_new(live, cnt);
        } else {
		update_changed(live, cnt, wlen, dir, cnt->reports, 
				old_proto->protocol);
	}

	return 0;
}

void update_liveflow_stats(LiveFlow *live, libtrace_packet_t *packet,
		LiveCounters *cnt, uint8_t dir) {

	/* We're in a new reporting period - reset our stats because we
 	 * only want the amount of traffic since we last reported */
	if (live->count_period != cnt->reports) {
                live->out_pbytes = 0;
                live->out_wbytes = 0;
                live->out_pkts = 0;
                live->in_pbytes = 0;
                live->in_pbytes = 0;
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

void destroy_live_flow(LiveFlow *live, LiveCounters *cnt) {

	/* Decrement the currently active flow counter for our matching
	 * protocol */
	if (live->init_dir == 0) {
		assert(OUT_CURR[PROTONUM] != 0);
		OUT_CURR[PROTONUM] --;
	} else {
		assert(IN_CURR[PROTONUM] != 0);
		IN_CURR[PROTONUM] --;
	}

	free(live);

}
