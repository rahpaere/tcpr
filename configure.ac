AC_INIT([TCPR], [1.0], [burgess@cs.cornell.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([tcpr.h])

AM_INIT_AUTOMAKE([foreign dist-bzip2 -Wall -Werror])
AM_CONFIG_HEADER([config.h])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AM_PROG_CC_C_O

AC_SEARCH_LIBS([nfnl_send], [nfnetlink],
  [AC_SEARCH_LIBS([nfq_open], [netfilter_queue],
    [AM_CONDITIONAL([WITH_NETFILTER], [true])],
    [AM_CONDITIONAL([WITH_NETFILTER], [false])])],
  [AM_CONDITIONAL([WITH_NETFILTER], [false])])

AC_SEARCH_LIBS([shm_open], [rt],
  [AM_CONDITIONAL([WITH_CHAT], [true])],
  [AM_CONDITIONAL([WITH_CHAT], [false])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
