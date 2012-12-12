#include <sys/param.h>
#include "lpicp.h"

/* Handy 32 bit byteswapping function - borrowed from libtrace */
static inline uint32_t byteswap32(uint32_t num)
{
	return ((num&0x000000FFU)<<24)
		| ((num&0x0000FF00U)<<8)
		| ((num&0x00FF0000U)>>8)
		| ((num&0xFF000000U)>>24);
}


/* Even handier 64 bit byte swapping function */
static inline uint64_t byteswap64(uint64_t num)
{
	return (byteswap32((num&0xFFFFFFFF00000000ULL)>>32))
		|((uint64_t)byteswap32(num&0x00000000FFFFFFFFULL)<<32);
}


#ifndef __BYTE_ORDER
#warning "Byte order is not defined"
#endif



uint64_t ntoh64(uint64_t num) {
#if __BYTE_ORDER == __BIG_ENDIAN
	return num;
#else
	return byteswap64(num);
#endif
}

uint64_t hton64(uint64_t num) {
#if __BYTE_ORDER == __BIG_ENDIAN
	return num;
#else
	return byteswap64(num);
#endif
}
