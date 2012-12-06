#ifndef LPICP_EXPORT_H
#define LPICP_EXPORT_H

#include "lpicp.h"
#include "live_common.h"

void lpicp_export_counters(LiveCounters *cnt, struct timeval tv, char *local_id, 
		uint32_t report_len);
		
#endif
