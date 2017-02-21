modprobe 8021q
vconfig add eth1 17
ip addr add 203.100.0.23/24 dev eth1.17
ip link set up eth1.17
ifconfig eth1.17 netmask 255.0.0.0
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl net.ipv4.conf.all.rp_filter=2
echo 1 > /proc/sys/net/ipv4/conf/eth1/log_martians

/etc/init.d/networking restart
