AC_INIT(libprotoident, 2.0.8, contact@wand.net.nz)

AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR(lib/libprotoident.cc)
AM_CONFIG_HEADER(config.h)

# Make sure we use the relatively silent automake output
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_PREFIX_DEFAULT(/usr/local/)

# Function that checks if the C++ compiler actually works - there's a bit of
# oversight in autoconf that will set the C++ compiler to g++ if no compiler
# is found, even if g++ is not present! So we need an extra test to make sure
# that the compiler works :(

AC_DEFUN([rw_PROG_CXX_WORKS],
[AC_REQUIRE([AC_PROG_CXX])dnl
AC_CACHE_CHECK([whether the C++ compiler works],
	[rw_cv_prog_cxx_works],
	[AC_LANG_PUSH([C++])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])],
		[rw_cv_prog_cxx_works=yes],
		[rw_cv_prog_cxx_works=no])
	AC_LANG_POP([C++])])
])



AC_PROG_CC
AC_PROG_CXX
rw_PROG_CXX_WORKS
AC_PROG_INSTALL

AC_LANG(C++)
AC_PROG_LIBTOOL

build_tools=yes

AC_ARG_WITH(tools,
	AS_HELP_STRING(--with-tools, install libprotoident tools),[
		if test "$withval" = yes
		then
			build_tools=yes
		else
			build_tools=no
		fi
])

AC_CHECK_LIB([trace], [trace_get_payload_length],,trace_found=0)

if test "$build_tools" = yes; then
	AC_CHECK_LIB([flowmanager], [lfm_release_flow],,lfm_found=0)
fi

AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h])

AC_CONFIG_FILES([Makefile lib/Makefile tools/Makefile 
		tools/find_unknown/Makefile tools/protoident/Makefile
		tools/arff/Makefile
		lib/udp/Makefile lib/tcp/Makefile])

if test "$trace_found" = 0; then
	AC_MSG_ERROR(Required library libtrace 3.0.7 or later not found; use LDFLAGS to specify library location)
fi

if test "$lfm_found" = 0; then
	AC_MSG_ERROR(Required library libflowmanager not found; use LDFLAGS to specify library location)
fi

AM_CONDITIONAL([BUILD_LPI_TOOLS], [test "$build_tools" = yes])

AC_SUBST([ADD_LIBS])
AC_SUBST([ADD_LDFLAGS])
AC_SUBST([ADD_INCLS])
AC_SUBST([LTLIBOBJS])

AC_OUTPUT


