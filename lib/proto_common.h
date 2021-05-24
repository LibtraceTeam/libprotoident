/*
 *
 * Copyright (c) 2011-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libprotoident.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */


#ifndef PROTO_COMMON_H_
#define PROTO_COMMON_H_

#include "libprotoident.h"

#ifndef __BYTE_ORDER
#include <endian.h>
#endif

#define ANY -1

#define MASKOCTET(x) \
        ((x) == ANY ? 0U : 255U)

#if __BYTE_ORDER == __BIG_ENDIAN
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


/** Byteswaps a 64-bit value.
 *
 * @param num           The value to be byteswapped.
 * @return The byteswapped 64-bit number
 *
 */
uint64_t byteswap64(uint64_t num);

/** Byteswaps a 32-bit value.
 *
 * @param num           The value to be byteswapped.
 * @return The byteswapped 32-bit number
 *
 */
uint32_t byteswap32(uint32_t num);

/** Byteswaps a 16-bit value.
 *
 * @param num           The value to be byteswapped.
 * @return The byteswapped 16-bit number
 *
 */
uint16_t byteswap16(uint16_t num);


#if __BYTE_ORDER == __BIG_ENDIAN
#define bswap_host_to_be64(num) ((uint64_t)(num))
#define bswap_host_to_le64(num) byteswap64(num)
#define bswap_host_to_be32(num) ((uint32_t)(num))
#define bswap_host_to_le32(num) byteswap32(num)
#define bswap_host_to_be16(num) ((uint16_t)(num))
#define bswap_host_to_le16(num) byteswap16(num)

#define bswap_be_to_host64(num) ((uint64_t)(num))
#define bswap_le_to_host64(num) byteswap64(num)
#define bswap_be_to_host32(num) ((uint32_t)(num))
#define bswap_le_to_host32(num) byteswap32(num)
#define bswap_be_to_host16(num) ((uint16_t)(num))
#define bswap_le_to_host16(num) byteswap16(num)

/* We use ntoh*() here, because the compiler may
 * attempt to optimise it
  */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define bswap_host_to_be64(num) (byteswap64(num))
#define bswap_host_to_le64(num) ((uint64_t)(num))
#define bswap_host_to_be32(num) (htonl(num))
#define bswap_host_to_le32(num) ((uint32_t)(num))
#define bswap_host_to_be16(num) (htons(num))
#define bswap_host_to_le16(num) ((uint16_t)(num))

#define bswap_be_to_host64(num) (byteswap64(num))
#define bswap_le_to_host64(num) ((uint64_t)(num))
#define bswap_be_to_host32(num) (ntohl(num))
#define bswap_le_to_host32(num) ((uint32_t)(num))
#define bswap_be_to_host16(num) (ntohs(num))
#define bswap_le_to_host16(num) ((uint16_t)(num))

#else
#error "Unknown byte order"
#endif


bool match_str_either(lpi_data_t *data, const char *string);
bool match_str_both(lpi_data_t *data, const char *string1,
        const char *string2);
bool match_chars_either(lpi_data_t *data, char a, char b, char c,
        char d);
bool match_chars_both(lpi_data_t *data, char a, char b, char c, char d);
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
bool match_yy_payload(uint32_t payload, uint32_t len);
#endif
