ip netns add PC1
ip netns add R1
ip netns add R2
ip netns add R3
ip netns add PC2
ip netns add R2-Mine
ip link add veth-PC1 type veth peer name veth-R1-left
ip link set veth-PC1 netns PC1
ip link set veth-R1-left netns R1
ip netns exec PC1 ip link set veth-PC1 up
ip netns exec PC1 ip addr add 192.168.1.2/24 dev veth-PC1
ip netns exec R1 ip link set veth-R1-left up
ip netns exec R1 ip addr add 192.168.1.1/24 dev veth-R1-left
ip link add veth-R1-right type veth peer name eth1
ip link set veth-R1-right netns R1
ip link set eth1 netns R2-Mine
ip netns exec R1 ip link set veth-R1-right up
ip netns exec R1 ip addr add 192.168.3.1/24 dev veth-R1-right
ip netns exec R2-Mine ip link set eth1 up
ip netns exec R2-Mine ip addr add 192.168.3.2/24 dev eth1
ip link add eth2 type veth peer name veth-R3-left
ip link set eth2 netns R2-Mine
ip link set veth-R3-left netns R3
ip netns exec R2-Mine ip link set eth2 up
ip netns exec R2-Mine ip addr add 192.168.4.1/24 dev eth2
ip netns exec R3 ip link set veth-R3-left up
ip netns exec R3 ip addr add 192.168.4.2/24 dev veth-R3-left
ip link add veth-R3-right type veth peer name veth-PC2-left
ip link set veth-R3-right netns R3
ip link set veth-PC2-left netns PC2
ip netns exec R3 ip link set veth-R3-right up
ip netns exec R3 ip addr add 192.168.5.2/24 dev veth-R3-right
ip netns exec PC2 ip link set veth-PC2-left up
ip netns exec PC2 ip addr add 192.168.5.1/24 dev veth-PC2-left
ip netns exec PC1 ip route add default via 192.168.1.1
ip netns exec PC2 ip route add default via 192.168.5.2
ip netns exec R1 sysctl -w net.ipv4.ip_forward=1
ip netns exec R3 sysctl -w net.ipv4.ip_forward=1
ip netns exec R1 echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
ip netns exec R3 echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
