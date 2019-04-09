bin_PROGRAMS=lpi_arff

man_MANS = lpi_arff.1
EXTRA_DIST = $(man_MANS)

include ../Makefile.tools
lpi_arff_SOURCES=lpi_arff.cc ../tools_common.cc
lpi_arff_LDADD = @ADD_LIBS@ -lprotoident
