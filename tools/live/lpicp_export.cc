#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include "lpicp.h"
#include "live_common.h" 

Lpi_collect_buffer_t buffer;
Lpicp_header_t *tmp_hdr;

void lpi_create_header (char *local_id )
{ 
	 /* Casting the buffer struct as a Lpicp_header_t and filling in the available 
	 * values*/
	tmp_hdr = (Lpicp_header_t *)&(buffer.buf[buffer.buf_used]);
	tmp_hdr->version = 1;
	tmp_hdr->record_type = LPICP_STATS;
	
	/* Restricting local_id to 100 characters */
	if ( strlen(local_id) > 100) {
		char tmp[100];
		strncpy(tmp, local_id, 100);
		local_id = tmp;		
	}	
	
	tmp_hdr->name_len = ntohs((uint16_t)strlen(local_id));
	tmp_hdr->reserved = 0;
	
	/* Incrementing buf_used with the size of the struct Lpicp_header_t, which
	 * is 8bytes */
	buffer.buf_used = sizeof(tmp_hdr);
}

void lpi_add_localId (char *local_id )
{
	/* Copy the local_id into the buffer and increment buffer.buf_used */
	char* s = strcpy(&buffer.buf[buffer.buf_used], local_id);
	buffer.buf_used += strlen(local_id);	
}

void lpi_add_subheader (struct timeval tv, uint32_t report_len, uint8_t dir, uint8_t metric)
{
	/* Casting the buffer struct as a Lpicp_stat_header_t and filling in the available 
	 * values*/
	Lpicp_stat_header_t *tmp_stat_hdr = 
			(Lpicp_stat_header_t *)&(buffer.buf[buffer.buf_used]);
	
	tmp_stat_hdr->secs = ntohl(tv.tv_sec);
	tmp_stat_hdr->usecs = ntohl(tv.tv_usec);
	tmp_stat_hdr->freq = ntohl(report_len);
	tmp_stat_hdr->dir = dir; 
	tmp_stat_hdr->metric = metric;
		
	/* Incrementing buf_used with the size of the struct Lpicp_stat_header_t, 
	 * which is 8bytes */
	 buffer.buf_used += sizeof(Lpicp_stat_header_t);
}

/*0 if you have to stop and start a new record
 1 if you managed to fit the current protocol in
*/
int lpi_print_proto_values(int index, uint64_t* array)
{
	/* Check that the total size of the bytes to be added for a particular 
	 * protocol(protocol name length, protocol name, value) won't exceed the 
	 * total number of bytes in buffer.buf */
	if ((1 + (strlen(lpi_print((lpi_protocol_t) index))) + sizeof(uint64_t)) 
				> (sizeof(buffer.buf) - buffer.buf_used)) {					
		return 0;
	} else {
		/* Adding length of the protocol name to the buffer */
		int len = (strlen(lpi_print((lpi_protocol_t) index)));
		uint8_t temp_len = len;
		
		uint8_t *proto_len = (uint8_t *)&(buffer.buf[buffer.buf_used]);
		*proto_len = temp_len;
		buffer.buf_used++;	
				
		/* Adding the protocol name */
		char* s = strcpy(&buffer.buf[buffer.buf_used], 
						lpi_print((lpi_protocol_t) index));
		buffer.buf_used += len;	
		
		/* Adding the value */
		uint64_t *value = (uint64_t *)&(buffer.buf[buffer.buf_used]);
		*value = hton64(array[index]);
		buffer.buf_used += sizeof(uint64_t);
		
		return 1;		
	}	
}

void lpi_export_single_counter (uint64_t* array, struct timeval tv, uint8_t dir,
				uint8_t metric, char* local_id, uint32_t report_len)
{
	uint32_t current_proto_id = 0;
	
	while (current_proto_id != LPI_PROTO_LAST ) {
		
		/* Resetting the buffer */
		buffer.buf_used = 0;	
		buffer.buf_exported = 0;
		
		/* Resetting the number of records exported in this packet */
		/* Set the number of exported records */
		int i = sizeof(Lpicp_header_t) + strlen(local_id);
		Lpicp_stat_header_t *tmp_stat_hdr = (Lpicp_stat_header_t *)&(buffer.buf[i]);
		tmp_stat_hdr->num_records = ntohs(0);
		int num_rec = 0;
		
		/* Adding the header, local_id and subheader to the buffer */
		lpi_create_header(local_id);
		lpi_add_localId(local_id);
		lpi_add_subheader(tv, report_len, dir, metric);
		
		for (current_proto_id; current_proto_id < LPI_PROTO_LAST; current_proto_id++) {		
			
			int ret = lpi_print_proto_values(current_proto_id, array);
			
			if (ret == 0) 
				break;	
			else
				num_rec++;
		}
		
		/* Set the total length of the packet */
		tmp_hdr->total_len = ntohs(buffer.buf_used);
		
		/* Set the number of records exported in this flow */
		tmp_stat_hdr->num_records = ntohs(num_rec);		
		write_buffer_network(&buffer);			
	}		 			
}

void lpicp_export_counters(LiveCounters *count, struct timeval tv, char *local_id, 
		uint32_t report_len)
{ 
	/* Exporting incoming packet counts */
	lpi_export_single_counter( count->in_pkt_count, tv, 1, LPICP_METRIC_PKTS, 
				local_id, report_len);	
				
	/* Outgoing packets */
	lpi_export_single_counter( count->out_pkt_count, tv, 0, LPICP_METRIC_PKTS, 
				local_id, report_len);	
				
	/* Incoming bytes (based on wire length) */
	lpi_export_single_counter( count->in_byte_count, tv, 1, LPICP_METRIC_BYTES, 
				local_id, report_len);	
          
	/* Outgoing bytes (based on wire length) */
	lpi_export_single_counter( count->out_byte_count, tv, 0, LPICP_METRIC_BYTES, 
				local_id, report_len);
	
	/* New flows originating from outside the local network */
        lpi_export_single_counter( count->in_flow_count, tv, 1, LPICP_METRIC_NEW_FLOWS, 
				local_id, report_len);
                
	/* New flows originating from inside the local network */
	lpi_export_single_counter( count->out_flow_count, tv, 0, LPICP_METRIC_NEW_FLOWS, 
				local_id, report_len);
				
	/* Peak values for in_current_flows since the last report */
	lpi_export_single_counter( count->in_peak_flows, tv, 1, LPICP_METRIC_PEAK_FLOWS, 
				local_id, report_len);
        
	/* Peak values for out_current_flows since the last report */
	lpi_export_single_counter( count->out_peak_flows, tv, 0, LPICP_METRIC_PEAK_FLOWS, 
				local_id, report_len);	

	/* Number of local IPs observed using each protocol */			
	lpi_export_single_counter( count->local_ips, tv, 1, LPICP_METRIC_ACTIVE_IPS, 
				local_id, report_len);	
}






