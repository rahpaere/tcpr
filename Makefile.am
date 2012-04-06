EXTRA_DIST = LICENSE

AM_CFLAGS = -Wall -Wextra -I$(srcdir)/include

tcpr_includedir=$(includedir)/tcpr
tcpr_include_HEADERS = \
	include/tcpr/filter.h \
	include/tcpr/module.h \
	include/tcpr/types.h

bin_PROGRAMS = tcpr-chat tcpr-control
tcpr_chat_SOURCES = src/chat.c
tcpr_control_SOURCES = src/control.c