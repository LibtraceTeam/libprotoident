bin_PROGRAMS=lpi_live

include_HEADERS=lpicp.h lpicp_export.h

include ../Makefile.tools
lpi_live_SOURCES=lpi_live.cc live_common.cc ../tools_common.cc 
lpi_live_LDADD = @ADD_LIBS@ -lprotoident -lpacketdump

if BUILD_COLLECTOR
bin_PROGRAMS+=lpi_collector
lpi_collector_SOURCES=collector.cc live_common.cc ../tools_common.cc \
	lpicp_export.cc 
lpi_collector_LDADD = @ADD_LIBS@ -lprotoident -lpacketdump -lwandevent
endif

