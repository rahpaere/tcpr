echo 0 | tee /proc/sys/net/ipv4/conf/*/send-redirects > /dev/null
echo 1 | tee /proc/sys/net/ipv4/ip_forward > /dev/null
openvpn --mktun --dev tcpr-test --dev-type tun --user `whoami`
ip link set tcpr-test up
ip addr add 10.0.0.1/24 dev tcpr-test
iptables -A FORWARD -s 10.0.0.1/24 -j NFQUEUE
