# Syn Scan
nmap 192.168.122.109

# Syn Flood (DoS)
sudo hping3 -S --flood -p 22 192.168.122.109

# Clear iptable
sudo iptables -F
sudo iptables -X

sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT