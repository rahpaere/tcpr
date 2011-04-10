EXTRA_DIST = LICENSE netperf-2.4.5-tcpr.patch
AM_CFLAGS = -D_BSD_SOURCE -Wall -Wextra

include_HEADERS = tcpr.h
bin_PROGRAMS =

TESTS = test/tcpr-test-setup-teardown \
		test/tcpr-test-app-data \
		test/tcpr-test-peer-data \
		test/tcpr-test-spurious-fins \
		test/tcpr-test-spurious-rsts \
		test/tcpr-test-recover-connection \
		test/tcpr-test-recover-send \
		test/tcpr-test-fin-simultaneous-recovery
check_PROGRAMS = $(TESTS)

test_tcpr_test_setup_teardown_SOURCES = test/tcpr-test-setup-teardown.c test/test.c test/test.h
test_tcpr_test_app_data_SOURCES = test/tcpr-test-app-data.c test/test.c test/test.h
test_tcpr_test_peer_data_SOURCES = test/tcpr-test-peer-data.c test/test.c test/test.h
test_tcpr_test_spurious_fins_SOURCES = test/tcpr-test-spurious-fins.c test/test.c test/test.h
test_tcpr_test_spurious_rsts_SOURCES = test/tcpr-test-spurious-rsts.c test/test.c test/test.h
test_tcpr_test_recover_connection_SOURCES = test/tcpr-test-recover-connection.c test/test.c test/test.h
test_tcpr_test_recover_send_SOURCES = test/tcpr-test-recover-send.c test/test.c test/test.h
test_tcpr_test_fin_simultaneous_recovery_SOURCES = test/tcpr-test-fin-simultaneous-recovery.c test/test.c test/test.h

if WITH_NETFILTER
  bin_PROGRAMS += tcpr-netfilter
  tcpr_netfilter_SOURCES = tcpr-netfilter.c tcpr.c
endif

if WITH_CHAT
  bin_PROGRAMS += tcpr-chat
  tcpr_chat_LIBS = -pthread
  tcpr_chat_CFLAGS = -pthread
endif
