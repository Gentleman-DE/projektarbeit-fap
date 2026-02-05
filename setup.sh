# dependencies
sudo apt install -y vim git hostapd iptables-persistent unbound ipset tshark dnsmasq dnsutils

# disable dnsmasq autostart
sudo systemctl disable dnsmasq
sudo systemctl disable unbound

# enable IP forwarding
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.conf
sudo sysctl -p

# set up NAT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# set forward rules (not sure if needed, because they should be the default)
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# persist
sudo netfilter-persistent save