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


inline bool match_str_either(lpi_data_t *data, const char *string);
inline bool match_str_both(lpi_data_t *data, const char *string1,
        const char *string2);
inline bool match_chars_either(lpi_data_t *data, char a, char b, char c,
        char d);
inline bool match_payload_length(uint32_t payload, uint32_t payload_len);
inline bool match_ip_address_both(lpi_data_t *data);
#endif
