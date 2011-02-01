SUBDIRS=

moduledir = $(prefix)/libprotoident/tcp

PROTOCOLS=

PROTOCOLS+= lpi_dns.la

module_LTLIBRARIES = $(PROTOCOLS)

lpi_dns_la_SOURCES = lpi_dns.cc
lpi_dns_la_LDFLAGS = -module -avoid-version @ADD_LDFLAGS@

AM_CXXFLAGS=-g -Wall -W -rdynamic
INCLUDES= @ADD_INCLS@ -I..


