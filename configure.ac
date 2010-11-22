AC_INIT(libprotoident, 1.0.0, contact@wand.net.nz)

AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR(lib/libprotoident.c)
AM_CONFIG_HEADER(config.h)

AC_PREFIX_DEFAULT(/usr/local/)

AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL

AC_LANG(C++)
AC_PROG_LIBTOOL

AC_CHECK_LIB([trace], [trace_create_packet],,trace_found=0)
AC_CHECK_LIB([flowmanager], [lfm_match_packet_to_flow],,lfm_found=0)
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h])

AC_CONFIG_FILES([Makefile lib/Makefile tools/Makefile 
		tools/find_unknown/Makefile tools/protoident/Makefile])

if test "$trace_found" = 0; then
	AC_MSG_ERROR(Required library libtrace not found; use LDFLAGS to specify library location)
fi

if test "$lfm_found" = 0; then
	AC_MSG_ERROR(Required library libflowmanager not found; use LDFLAGS to specify library location)
fi

AC_SUBST([ADD_LIBS])
AC_SUBST([ADD_LDFLAGS])
AC_SUBST([ADD_INCLS])
AC_SUBST([LTLIBOBJS])

AC_OUTPUT


