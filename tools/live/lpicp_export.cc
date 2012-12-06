#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include "lpicp.h"
#include "live_common.h" 

Lpi_collect_buffer_t buffer;

void lpicp_export_counters(LiveCounters *cnt, struct timeval tv, char *local_id, 
		uint32_t report_len)
{
	/*uint8_t version;
	enum lpicp_record record_type;
	uint16_t total_len;
	uint16_t name_length;
	uint16_t reserved;
	 */
	
	/* Casting the buffer struct as a Lpicp_header_t and filling in the available 
	 * values*/
	Lpicp_header_t *tmp_hdr = (Lpicp_header_t *)&(buffer.buf[buffer.buf_used]);
	tmp_hdr->version = 1;
	tmp_hdr->record_type = LPICP_STATS;
	
	/* Restricting local_id to 100 characters */
	if ( strlen(local_id) > 100) {
		char tmp[100];
		strncpy(tmp, local_id, 100);
		local_id = tmp;		
	}	
	
	tmp_hdr->name_length = ntohs((uint16_t)strlen(local_id));
	tmp_hdr->reserved = 0;
	
	/* Incrementing buf_used with the size of the struct Lpicp_header_t, which
	 * is 8bytes */
	buffer.buf_used = sizeof(tmp_hdr);
	
	/* Copy the local_id into the buffer and increment buffer.buf_used */
	char* s = strcpy(&buffer.buf[buffer.buf_used], local_id);
	buffer.buf_used += strlen(local_id);
		
	/* Casting the buffer struct as a Lpicp_stat_header_t and filling in the available 
	 * values*/
	 Lpicp_stat_header_t *tmp_stat_hdr = 
			(Lpicp_stat_header_t *)&(buffer.buf[buffer.buf_used]);
	/*uint32_t secs;
	uint32_t usecs;
	uint32_t freq;
	uint8_t dir;
	enum lpicp_metric metric;
	uint16_t num_records;*/
	tmp_stat_hdr->secs = ntohl(tv.tv_sec);
	tmp_stat_hdr->usecs = ntohl(tv.tv_usec);
	tmp_stat_hdr->freq = ntohl(report_len);
	tmp_stat_hdr->dir = 0; // ??
	tmp_stat_hdr->metric = LPICP_METRIC_PKTS; // ??
	tmp_stat_hdr->num_records = 0; // ??
	
	/* Incrementing buf_used with the size of the struct Lpicp_stat_header_t, 
	 * which is 8bytes */
	 buffer.buf_used += sizeof(tmp_stat_hdr);
	 
	 tmp_hdr->total_len = ntohs(buffer.buf_used);
	 
	 write_buffer_network(&buffer);	
}


