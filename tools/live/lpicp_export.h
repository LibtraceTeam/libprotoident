#ifndef LPICP_EXPORT_H
#define LPICP_EXPORT_H

#include "lpicp.h"
#include "live_common.h"

void lpicp_export_counters(LiveCounters *cnt, struct timeval tv, char *local_id, 
		uint32_t report_len);
		
int lpi_export_single_counter (uint64_t * array, struct timeval tv, uint8_t dir,
				uint8_t metric, char* local_id, uint32_t report_len);
				
void lpi_create_header (char *local_id );

void lpi_add_localId (char *local_id );

void lpi_add_subheader (struct timeval tv, uint32_t report_len, uint8_t dir, 
				uint8_t metric, uint32_t freq);
		
#endif
