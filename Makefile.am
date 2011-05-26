EXTRA_DIST = LICENSE netperf-2.4.5-tcpr.patch
AM_CFLAGS = -D_BSD_SOURCE -Wall -Wextra -I$(srcdir)/include

include_HEADERS = include/tcpr/types.h include/tcpr/filter.h

bin_PROGRAMS = tcpr-chat tcpr-filter

tcpr_chat_SOURCES = src/chat.c
tcpr_filter_SOURCES = src/filter.c src/tcpr.c src/md5/md5.c src/md5util.c

TESTS = test/tcpr-test-setup-teardown \
	test/tcpr-test-app-data \
	test/tcpr-test-peer-data \
	test/tcpr-test-spurious-fins \
	test/tcpr-test-spurious-rsts \
	test/tcpr-test-recover-connection \
	test/tcpr-test-recover-peer-send \
	test/tcpr-test-recover-app-send \
	test/tcpr-test-graceful-shutdown \
	test/tcpr-test-filter-recovery \
	test/tcpr-test-simultaneous-recovery
check_PROGRAMS = $(TESTS)

test_tcpr_test_setup_teardown_SOURCES = \
	test/tcpr-test-setup-teardown.c test/test.c test/test.h src/md5util.h src/md5util.c src/md5/md5.h src/md5/md5.c src/md5/global.h
test_tcpr_test_app_data_SOURCES = \
	test/tcpr-test-app-data.c test/test.c test/test.h src/md5util.h src/md5util.c src/md5/md5.h src/md5/md5.c src/md5/global.h
test_tcpr_test_peer_data_SOURCES = \
	test/tcpr-test-peer-data.c test/test.c test/test.h src/md5util.h src/md5util.c src/md5/md5.h src/md5/md5.c src/md5/global.h
test_tcpr_test_spurious_fins_SOURCES = \
	test/tcpr-test-spurious-fins.c test/test.c test/test.h src/md5util.h src/md5util.c src/md5/md5.h src/md5/md5.c src/md5/global.h
test_tcpr_test_spurious_rsts_SOURCES = \
	test/tcpr-test-spurious-rsts.c test/test.c test/test.h src/md5util.h src/md5util.c src/md5/md5.h src/md5/md5.c src/md5/global.h
test_tcpr_test_recover_connection_SOURCES = \
	test/tcpr-test-recover-connection.c test/test.c test/test.h src/md5util.h src/md5util.c src/md5/md5.h src/md5/md5.c src/md5/global.h
test_tcpr_test_recover_peer_send_SOURCES = \
	test/tcpr-test-recover-peer-send.c test/test.c test/test.h src/md5util.h src/md5util.c src/md5/md5.h src/md5/md5.c src/md5/global.h
test_tcpr_test_recover_app_send_SOURCES = \
	test/tcpr-test-recover-app-send.c test/test.c test/test.h src/md5util.h src/md5util.c src/md5/md5.h src/md5/md5.c src/md5/global.h
test_tcpr_test_graceful_shutdown_SOURCES = \
	test/tcpr-test-graceful-shutdown.c test/test.c test/test.h src/md5util.h src/md5util.c src/md5/md5.h src/md5/md5.c src/md5/global.h
test_tcpr_test_filter_recovery_SOURCES = \
	test/tcpr-test-filter-recovery.c test/test.c test/test.h src/md5util.h src/md5util.c src/md5/md5.h src/md5/md5.c src/md5/global.h
test_tcpr_test_simultaneous_recovery_SOURCES = \
	test/tcpr-test-simultaneous-recovery.c test/test.c test/test.h src/md5util.h src/md5util.c src/md5/md5.h src/md5/md5.c src/md5/global.h
