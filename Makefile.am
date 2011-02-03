EXTRA_DIST = LICENSE
AM_CFLAGS = -D_BSD_SOURCE

include_HEADERS = tcpr.h
bin_PROGRAMS =

if WITH_NETFILTER
  bin_PROGRAMS += tcpr-netfilter
  tcpr_netfilter_SOURCES = tcpr-netfilter.c tcpr.c
endif

if WITH_APPLICATION
  bin_PROGRAMS += tcpr-application
  tcpr_application_LIBS = -pthread
  tcpr_application_CFLAGS = -pthread
endif
