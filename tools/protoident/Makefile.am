bin_PROGRAMS=lpi_protoident

man_MANS = lpi_protoident.1
EXTRA_DIST = $(man_MANS)

include ../Makefile.tools
lpi_protoident_SOURCES=lpi_protoident.cc ../tools_common.cc
lpi_protoident_LDADD = @ADD_LIBS@ -lprotoident
