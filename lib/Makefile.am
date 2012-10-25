SUBDIRS=tcp udp

lib_LTLIBRARIES=libprotoident.la
include_HEADERS=libprotoident.h

libprotoident_la_SOURCES=libprotoident.h libprotoident.cc \
	proto_common.cc proto_common.h \
	proto_manager.cc proto_manager.h

INCLUDES=@ADD_INCLS@
libprotoident_la_LIBADD = @ADD_LIBS@ tcp/libprotoident_tcp.la \
	udp/libprotoident_udp.la
libprotoident_la_LDFLAGS = @ADD_LDFLAGS@ -version-info 2:6:0
