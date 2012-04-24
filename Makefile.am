EXTRA_DIST = LICENSE module/Makefile module/module.c module/filter.c

AM_CFLAGS = -Wall -Wextra -I$(srcdir)/include

xtablesdir = /lib/xtables
xtables_LTLIBRARIES = libxt_TCPR.la
libxt_TCPR_la_SOURCES = module/libxt_TCPR.c
libxt_TCPR_la_LIBADD = -lxtables

tcpr_includedir=$(includedir)/tcpr
tcpr_include_HEADERS = include/tcpr/filter.h include/tcpr/types.h

bin_PROGRAMS = tcpr-chat tcpr-control tcpr-bridge
tcpr_chat_SOURCES = src/chat.c
tcpr_control_SOURCES = src/control.c
tcpr_bridge_SOURCES = src/bridge.c
