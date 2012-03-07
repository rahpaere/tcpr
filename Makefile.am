EXTRA_DIST = LICENSE

AM_CFLAGS = -D_BSD_SOURCE -Wall -Wextra -I$(srcdir)/include
LDADD = libtcpr.a

dist_bin_SCRIPTS = \
	scripts/tcpr-setup-iptables \
	scripts/tcpr-restore-iptables

tcpr_includedir=$(includedir)/tcpr
tcpr_include_HEADERS = \
	include/tcpr/application.h \
	include/tcpr/filter.h \
	include/tcpr/types.h

lib_LIBRARIES = libtcpr.a
libtcpr_a_SOURCES = \
	lib/tcpr.c \
	lib/application.c

bin_PROGRAMS = \
	tcpr-benchmark \
	tcpr-chat \
	tcpr-control \
	tcpr-filter
tcpr_benchmark_SOURCES = src/benchmark.c
tcpr_chat_SOURCES = src/chat.c
tcpr_control_SOURCES = src/control.c
tcpr_filter_SOURCES = src/filter.c

noinst_PROGRAMS = \
	examples/client \
	examples/server
examples_client_SOURCES = examples/client.c
examples_server_SOURCES = examples/server.c
