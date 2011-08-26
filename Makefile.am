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
	tcpr-chat \
	tcpr-debug \
	tcpr-filter \
	tcpr-benchmark-latency \
	tcpr-benchmark-recovery \
	tcpr-benchmark-throughput
tcpr_chat_SOURCES = src/chat.c
tcpr_debug_SOURCES = src/debug.c
tcpr_filter_SOURCES = src/filter.c
tcpr_benchmark_latency_SOURCES = src/latency.c
tcpr_benchmark_recovery_SOURCES = src/recovery.c
tcpr_benchmark_throughput_SOURCES = src/throughput.c
