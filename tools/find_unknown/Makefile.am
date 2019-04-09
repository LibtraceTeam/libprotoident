bin_PROGRAMS=lpi_find_unknown 

man_MANS = lpi_find_unknown.1
EXTRA_DIST = $(man_MANS)

include ../Makefile.tools
lpi_find_unknown_SOURCES=lpi_find_unknown.cc ../tools_common.cc
lpi_find_unknown_LDADD = @ADD_LIBS@ -lprotoident
