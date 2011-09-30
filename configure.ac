AC_INIT([TCPR], [1.0], [Robert Surton <burgess@cs.cornell.edu>])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([include/tcpr/types.h])

AM_INIT_AUTOMAKE([foreign dist-bzip2 subdir-objects -Wall -Werror])
AM_CONFIG_HEADER([config.h])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_CC_C_O

AC_SEARCH_LIBS([nfnl_send], [nfnetlink],,
		AC_MSG_ERROR([The nfnetlink library is required.]))
AC_SEARCH_LIBS([nfq_open], [netfilter_queue],,
		AC_MSG_ERROR([The netfilter_queue library is required.]))
AC_SEARCH_LIBS([clock_gettime], [rt],,
		AC_MSG_ERROR([The clock_gettime function is required.]))

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
