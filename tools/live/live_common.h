#ifndef LIVE_COMMON_H_
#define LIVE_COMMON_H_

#include <libprotoident.h>

typedef struct counters {

        uint64_t in_pkt_count[LPI_PROTO_LAST];
        uint64_t out_pkt_count[LPI_PROTO_LAST];
        uint64_t in_byte_count[LPI_PROTO_LAST];
        uint64_t out_byte_count[LPI_PROTO_LAST];
        uint64_t in_flow_count[LPI_PROTO_LAST];
        uint64_t out_flow_count[LPI_PROTO_LAST];

        uint64_t in_current_flows[LPI_PROTO_LAST];
        uint64_t out_current_flows[LPI_PROTO_LAST];
        uint64_t in_peak_flows[LPI_PROTO_LAST];
        uint64_t out_peak_flows[LPI_PROTO_LAST];

} LiveCounters;

typedef struct live {
        uint8_t init_dir;
        
        char local_ip[INET6_ADDRSTRLEN];
        char ext_ip[INET6_ADDRSTRLEN]; 

        uint64_t in_pkts;
        uint64_t out_pkts;
        uint64_t in_wbytes;
        uint64_t in_pbytes;
        uint64_t out_wbytes;
        uint64_t out_pbytes;
        double start_ts;
        uint32_t start_period;
        uint32_t count_period;
        lpi_data_t lpi;
        lpi_module_t *proto;
} LiveFlow;


void init_live_flow(Flow *f, uint8_t dir, double ts, uint32_t period);
void reset_counters(LiveCounters *cnt, bool wipe_all);
void dump_counters_stdout(LiveCounters *cnt, double ts, char *local_id, 
                uint32_t report_freq);
int update_protocol_counters(LiveFlow *live, LiveCounters *cnt, uint32_t wlen, 
		uint32_t plen, uint8_t dir, uint32_t period);
void destroy_live_flow(LiveFlow *live, LiveCounters *cnt);

#endif
