#ifndef LPICP_H
#define LPICP_H

#include <stdint.h>

enum lpicp_record {
        LPICP_STATS,
        LPICP_ONGOING,
        LPICP_EXPIRED 
};

enum lpicp_metric {
	LPICP_METRIC_PKTS,
	LPICP_METRIC_BYTES,	
	LPICP_METRIC_NEW_FLOWS,
	LPICP_METRIC_CURR_FLOWS,
	LPICP_METRIC_PEAK_FLOWS
};

/* Structure which defines a custom header used at the start of a packet which 
 * contains flow records that are to be exported over a network.
 * It contains the information that is common for all the flows. */
typedef struct __attribute__((packed)) lpicp_header {
	
	uint8_t version;
	uint8_t record_type;
	uint16_t total_len;
	uint16_t name_len;
	uint16_t reserved;

} Lpicp_header_t ;

/* Structure which defines a stat header used for LPICP_STATS records */
typedef struct __attribute__((packed)) lpicp_stat_header {
	uint32_t secs;
	uint32_t usecs;
	uint32_t freq;
	uint8_t dir;
	uint8_t metric;
	uint16_t num_records;		
} Lpicp_stat_header_t;

/* Function to convert a uint64_t to Host Byte Order from Network Byte Order */
uint64_t ntoh64(uint64_t num);

/* Function to convert a uint64_t to Network Byte Order from Host Byte Order */
uint64_t hton64(uint64_t num);
#endif
