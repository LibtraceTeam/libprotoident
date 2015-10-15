/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011-2015 The University of Waikato, Hamilton, New Zealand.
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


#ifndef PROTO_COMMON_H_
#define PROTO_COMMON_H_

#include "libprotoident.h"

#define ANY -1

#define MASKOCTET(x) \
        ((x) == ANY ? 0U : 255U)

#if BYTE_ORDER == BIG_ENDIAN
#define FORMUP(a,b,c,d) \
        (unsigned)((((a)&0xFF)<<24)|(((b)&0xFF)<<16)|(((c)&0xFF)<<8)|((d)&0xFF))
#else
#define FORMUP(a,b,c,d) \
	(unsigned)((((d)&0xFF)<<24)|(((c)&0xFF)<<16)|(((b)&0xFF)<<8)|((a)&0xFF))
#endif


#define FORMUPMASK(a,b,c,d) \
        FORMUP(MASKOCTET(a),MASKOCTET(b),MASKOCTET(c),MASKOCTET(d))
#define MATCH(x,a,b,c,d) \
                ((x&FORMUPMASK(a,b,c,d))==(FORMUP(a,b,c,d)&FORMUPMASK(a,b,c,d)))

#define MATCHSTR(x,st) \
        (memcmp(&(x),(st),sizeof(x))==0)


bool match_str_either(lpi_data_t *data, const char *string);
bool match_str_both(lpi_data_t *data, const char *string1,
        const char *string2);
bool match_chars_either(lpi_data_t *data, char a, char b, char c,
        char d);
bool match_payload_length(uint32_t payload, uint32_t payload_len);
bool match_ip_address_both(lpi_data_t *data);
bool match_file_header(uint32_t payload);
bool match_http_request(uint32_t payload, uint32_t len);
bool valid_http_port(lpi_data_t *data);
bool match_ssl(lpi_data_t *data);
bool match_dns(lpi_data_t *data);
bool match_tds_request(uint32_t payload, uint32_t len);
bool match_8000_payload(uint32_t payload, uint32_t len);
bool match_youku_payload(uint32_t payload, uint32_t len);
bool match_emule(lpi_data_t *data);
bool match_kaspersky(lpi_data_t *data);
bool match_tpkt(uint32_t payload, uint32_t len);
bool match_qqlive_payload(uint32_t payload, uint32_t len);
#endif
