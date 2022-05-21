# temp

# iptables
iptables -t nat -A PREROUTING -i eth0 -j DNAT --to 1.30.50.70
iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 200.30.50.70

# dns
yum -y install bind
vi /etc/resolv.conf
