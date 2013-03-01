EXTRA_DIST = LICENSE module/Makefile module/module.c module/filter.c

AM_CFLAGS = -Wall -Wextra -I$(srcdir)/include

xtablesdir = /lib/xtables
xtables_LTLIBRARIES = libxt_TCPR.la
libxt_TCPR_la_SOURCES = module/libxt_TCPR.c
libxt_TCPR_la_LIBADD = -lxtables

tcpr_includedir=$(includedir)/tcpr
tcpr_include_HEADERS = include/tcpr/filter.h include/tcpr/types.h
noinst_HEADERS = include/tcpr/util.h

bin_PROGRAMS = \
	tcpr-get \
	tcpr-bind \
	tcpr-ack \
	tcpr-done \
	tcpr-kill \
	tcpr-print \
	tcpr-put \
	tcpr-chat \
	tcpr-bridge \
	tcpr-benchmark
tcpr_get_SOURCES = src/get.c src/util.c
tcpr_bind_SOURCES = src/bind.c src/util.c
tcpr_ack_SOURCES = src/ack.c src/util.c
tcpr_done_SOURCES = src/done.c src/util.c
tcpr_kill_SOURCES = src/kill.c src/util.c
tcpr_print_SOURCES = src/print.c src/util.c
tcpr_put_SOURCES = src/put.c src/util.c
tcpr_chat_SOURCES = src/chat.c
tcpr_bridge_SOURCES = src/bridge.c
tcpr_benchmark_SOURCES = src/benchmark.c
