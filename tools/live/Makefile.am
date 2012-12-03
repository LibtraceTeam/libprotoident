bin_PROGRAMS=lpi_live

include ../Makefile.tools
lpi_live_SOURCES=lpi_live.cc live_common.cc ../tools_common.cc
lpi_live_LDADD = @ADD_LIBS@ -lprotoident -lpacketdump

if BUILD_COLLECTOR
bin_PROGRAMS+=lpi_collector
lpi_collector_SOURCES=collector.cc live_common.cc ../tools_common.cc
lpi_collector_LDADD = @ADD_LIBS@ -lprotoident -lpacketdump -lwandevent
endif

