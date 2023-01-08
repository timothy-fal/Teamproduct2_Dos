import os

os.system("iptables -P INPUT DROP")
os.system("iptables -P FORWARD DROP")
os.system("iptables -P OUTPUT ACCEPT")
os.system("iptables -A INPUT -i eth0 -p tcp --dport 80 -j ACCEPT")
os.system("iptables -A INPUT -i eth0 -p tcp --dport 443 -j ACCEPT")
os.system("iptables -A INPUT -p icmp --icmp-type 8 -s 0/0 -d 172.17.0.3 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT")
os.system("iptables -A OUTPUT -p icmp --icmp-type 0 -s 172.17.0.3 -d 0/0 -m state --state ESTABLISHED,RELATED -j ACCEPT")
os.system("iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 443")
os.system("iptables-save")
