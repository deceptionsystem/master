tc qdisc del dev eth1 root

tc qdisc add dev eth1 root handle 1: prio
tc filter add dev eth1 parent 1: protocol ip prio 1 u32 flowid 1:1 match ip src 203.100.0.23
tc filter add dev eth1 parent 1: protocol ip prio 1 u32 flowid 1:2 match ip src 203.100.0.24
tc qdisc add dev eth1 parent 1:1 handle 10: netem delay 50ms 10ms
tc qdisc add dev eth1 parent 1:2 handle 20: netem delay 100ms 10ms

#tc filter add dev eth1 parent 1:0 prio 1 protocol 802.1q u32
#tc filter add dev eth1 parent 1:0 prio 1 protocol 802.1q u32 match flowid 1:17


