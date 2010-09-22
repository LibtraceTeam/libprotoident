lib_LTLIBRARIES=libprotoident.la
include_HEADERS=libprotoident.h

libprotoident_la_SOURCES=libprotoident.h libprotoident.c proto_tcp.c \
	proto_tcp.h proto_udp.c proto_udp.h proto_common.c proto_common.h

INCLUDES=@ADD_INCLS@
libprotoident_la_LIBADD = @ADD_LIBS@
libprotoident_la_LDFLAGS = @ADD_LDFLAGS@ -version-info 1:0:0
