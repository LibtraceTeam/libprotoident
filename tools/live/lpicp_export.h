#ifndef LPICP_EXPORT_H
#define LPICP_EXPORT_H

#include "lpicp.h"
#include "live_common.h"

/*
 * Exports all counters defined in the struct LiveCounters.
 * 
 * cnt is the struct which contains all the arrays with the protocol values.
 * tv is the timestamp when the counters were last reset.
 * local_id is a string that will identify this particular measurement process,
 * 	e.g. the source of the packets
 * report_len  is the number of seconds that have passed since the counters
 * 	were last reset (this will be included in the output so users can do
 *	rate calculations). 
 */
void lpicp_export_counters(LiveCounters *cnt, struct timeval tv, char *local_id, 
		uint32_t report_len);


/* Exports a single counter over the network by adding data(protocol length, 
 * name, and value) to the buffer for each of the protocols supported by Libprotoident.
 * 
 * array is the array of counters that needs to be exported, e.g. in_pkt_count[].
 * tv is the timestamp when the counters were last reset.
 * dir is the direction of the most recent packet.
 * metric ?? 
 * local_id is a string that will identify this particular measurement process,
 * 	e.g. the source of the packets
 * report_len  is the number of seconds that have passed since the counters
 * 	were last reset (this will be included in the output so users can do
 *	rate calculations). 
 */		
void lpi_export_single_counter (uint64_t * array, struct timeval tv, uint8_t dir,
				uint8_t metric, char* local_id, uint32_t report_len);


/* Creates a header for the custom buffer which will contain flow records.
 * This header contains the information that is common for all flows.
 * 
 * local_id is a string that will identify this particular measurement process,
 * 	e.g. the source of the packets
 */			
void lpi_create_header (char *local_id );

/* Adds the local_id after the header has been added to the buffer. 
 * 
 * local_id is a string that will identify this particular measurement process,
 * 	e.g. the source of the packets
 */
void lpi_add_localId (char *local_id );


/* Adds the subheader to the buffer after the header and local_id have been added.
 * 
 * tv is the timestamp when the counters were last reset.
 * report_len  is the number of seconds that have passed since the counters
 * 	were last reset (this will be included in the output so users can do
 *	rate calculations).
 * dir is the direction of the most recent packet.
 * metric ?? 
 */
void lpi_add_subheader (struct timeval tv, uint32_t report_len, uint8_t dir, 
				uint8_t metric);
	
				
/* Appends the protocol details(protocol name length, name and value) from the 
 * array in the arguments to the buffer which is to be exported over the network.
 * 
 * index is the index of the protocol which is used to retrieve the protocol length,
 * name and value from the array.
 * array is the array of counters that needs to be exported, e.g. in_pkt_count[].
 * 
 * Returns 0 if the entry for a protocol would overflow the buffer, or else 1.
 */			
int lpi_print_proto_values(int index, uint64_t* array);
		
#endif
