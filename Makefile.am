EXTRA_DIST = LICENSE netperf-2.4.5-tcpr.patch
AM_CFLAGS = -D_BSD_SOURCE -Wall -Wextra

include_HEADERS = tcpr.h
bin_PROGRAMS = tcpr-test
tcpr_test_SOURCES = tcpr-test.c

if WITH_NETFILTER
  bin_PROGRAMS += tcpr-netfilter
  tcpr_netfilter_SOURCES = tcpr-netfilter.c tcpr.c
endif

if WITH_CHAT
  bin_PROGRAMS += tcpr-chat
  tcpr_chat_LIBS = -pthread
  tcpr_chat_CFLAGS = -pthread
endif
