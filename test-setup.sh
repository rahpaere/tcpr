echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects > /dev/null
echo 1 | tee /proc/sys/net/ipv4/ip_forward > /dev/null
openvpn --mktun --dev tcpr-test --dev-type tun --user $1
ip link set tcpr-test up
ip addr add 10.10.10.1/24 dev tcpr-test
iptables -A FORWARD -s 10.10.10.1/24 -j NFQUEUE
