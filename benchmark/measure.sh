#! /bin/sh

EXTERNAL=127.0.0.1
INTERNAL=127.0.0.2
PEER=127.0.0.1

PASSPORT=6666
RAWPORT=7777
PORT=8888
PEERPORT=9999

RAWARGS="-b $EXTERNAL:$RAWPORT -c $PEER:$PEERPORT -T"
PASSARGS="-b $EXTERNAL:$PASSPORT -c $PEER:$PEERPORT -T"
NOCHECKARGS="-b $INTERNAL:$PORT -c $PEER:$PEERPORT -C"
ARGS="-b $INTERNAL:$PORT -c $PEER:$PEERPORT"
PEERARGS="-b $PEER:$PEERPORT -p"

restore_firewall() {
    echo Restoring firewall.
    if test -f iptables.saved
    then
	sudo iptables-restore < iptables.saved &&
	rm iptables.saved
    fi
}

stop_filter() {
    echo Stopping filter.
    if test -n "$FILTER"
    then
	kill $FILTER &&
	wait $FILTER &&
	unset FILTER
    fi
}

trap "stop_filter; restore_firewall" INT QUIT TERM EXIT

echo Configuring firewall.
test ! -f iptables.saved && sudo iptables-save > iptables.saved
sudo iptables-restore <<EOF
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -d $EXTERNAL/32 -p tcp -m tcp --dport $PORT -j NFQUEUE --queue-num 0
-A OUTPUT -s $INTERNAL/32 -p tcp -m tcp --sport $PORT -j NFQUEUE --queue-num 0
-A INPUT -d $EXTERNAL/32 -p tcp -m tcp --dport $PASSPORT -j NFQUEUE --queue-num 0
-A OUTPUT -s $EXTERNAL/32 -p tcp -m tcp --sport $PASSPORT -j NFQUEUE --queue-num 0
COMMIT
EOF

echo
echo Measuring raw TCP.

echo Benchmarking latency.
ssh -f $PEER tcpr-latency $PEERARGS > tcpr-raw-latency-peer.dat
sleep 1
tcpr-latency $RAWARGS > tcpr-raw-latency.dat

echo Benchmarking send throughput.
ssh -f $PEER tcpr-throughput $PEERARGS > tcpr-raw-send-peer.dat
sleep 1
tcpr-throughput $RAWARGS > tcpr-raw-send.dat

echo Benchmarking receive throughput.
ssh -f $PEER tcpr-throughput $PEERARGS -r > tcpr-raw-receive-peer.dat
sleep 1
tcpr-throughput $RAWARGS -r > tcpr-raw-receive.dat

echo
echo Measuring passthrough filter.

echo Running filter.
tcpr-filter -p 2>/dev/null & FILTER=$!
sleep 1

echo Benchmarking latency.
ssh -f $PEER tcpr-latency $PEERARGS > tcpr-pass-latency-peer.dat
sleep 1
tcpr-latency $PASSARGS > tcpr-pass-latency.dat

echo Benchmarking send throughput.
ssh -f $PEER tcpr-throughput $PEERARGS > tcpr-pass-send-peer.dat
sleep 1
tcpr-throughput $PASSARGS > tcpr-pass-send.dat

echo Benchmarking receive throughput.
ssh -f $PEER tcpr-throughput $PEERARGS -r > tcpr-pass-receive-peer.dat
sleep 1
tcpr-throughput $PASSARGS -r > tcpr-pass-receive.dat

stop_filter

echo
echo Measuring TCPR with no checkpointing.

echo Running filter.
tcpr-filter -i $INTERNAL -e $EXTERNAL 2>/dev/null & FILTER=$!
sleep 1

echo Benchmarking latency.
ssh -f $PEER tcpr-latency $PEERARGS > tcpr-nocheck-latency-peer.dat
sleep 1
tcpr-latency $NOCHECKARGS > tcpr-nocheck-latency.dat

echo Benchmarking send throughput.
ssh -f $PEER tcpr-throughput $PEERARGS > tcpr-nocheck-send-peer.dat
sleep 1
tcpr-throughput $NOCHECKARGS > tcpr-nocheck-send.dat

echo Benchmarking receive throughput.
ssh -f $PEER tcpr-throughput $PEERARGS -r > tcpr-nocheck-receive-peer.dat
sleep 1
tcpr-throughput $NOCHECKARGS -r > tcpr-nocheck-receive.dat

echo
echo Measuring TCPR.

echo Benchmarking latency.
ssh -f $PEER tcpr-latency $PEERARGS > tcpr-latency-peer.dat
sleep 1
tcpr-latency $ARGS > tcpr-latency.dat

echo Benchmarking send throughput.
ssh -f $PEER tcpr-throughput $PEERARGS > tcpr-send-peer.dat
sleep 1
tcpr-throughput $ARGS > tcpr-send.dat

echo Benchmarking receive throughput.
ssh -f $PEER tcpr-throughput $PEERARGS -r > tcpr-receive-peer.dat
sleep 1
tcpr-throughput $ARGS -r > tcpr-receive.dat

echo Benchmarking recovery.
ssh -f $PEER tcpr-recovery $PEERARGS
sleep 1
tcpr-recovery $ARGS > tcpr-recovery.dat

echo
echo Done.
