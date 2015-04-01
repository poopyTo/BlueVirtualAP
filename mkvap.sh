#!/usr/bin/bash

# Install dependencies
sudo apt-get install hostapd isc-dhcp-server

# Configure dhcp server
if ! grep -q "subnet 10.10.0.0 netmask 255.255.255.0 {
range 10.10.0.2 10.10.0.16;
option domain-name-servers 8.8.4.4, 208.67.222.222;
options routers 10.10.0.1;
}" /etc/dhcp/dhcpd.conf ; then
sudo sh -c "echo 'subnet 10.10.0.0 netmask 255.255.255.0 {
range 10.10.0.2 10.10.0.16;
option domain-name-servers 8.8.4.4, 208.67.222.222;
options routers 10.10.0.1;
}' >> /etc/network/interfaces"
fi

# Configure static IP for the AP
if ! grep -q "auto $1
iface $1 inet static
hostapd /etc/hostapd/hostapd.conf
address 10.0.0.1
netmask 255.255.255.0" /etc/network/interfaces ; then
sudo sh -c "echo 'auto $1
iface $1 inet static
hostapd /etc/hostapd/hostapd.conf
address 10.0.0.1
netmask 255.255.255.0' >> /etc/network/interfaces"
fi

# Restart the DHCP server and route interface
sudo nmcli nm wifi off
sudo rfkill unblock wlan
sudo ifconfig $1 10.0.0.1 netmask 255.255.255.0 up # Init the interface
sleep 1
sudo /etc/init.d/isc-dhcp-server restart # Restart dhcp server
sudo sysctl -w net.ipv4.ip_forward=1 # Allow IP forwarding
sudo iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o $2 -j MASQUERADE # Routing rule

# Configure hostapd
if [ -f /etc/hostapd/hostapd.conf ]; then # if config exists, remove
	sudo rm /etc/hostapd/hostapd.conf
fi
sudo touch /etc/hostapd/hostapd.conf # start from scratch config
sudo sh -c "echo 'interface=$1
driver=nl80211
ssid=BlueVAP
hw_mode=g
channel=11' >> /etc/hostapd/hostapd.conf"

# Configure the hostapd daemon
if ! grep -q "/etc/hostapd/hostapd.conf" /etc/default/hostapd ; then
	sudo sh -c "echo 'DAEMON_CONF='/etc/hostapd/hostapd.conf'' >> /etc/default/hostapd"
fi

# Finally, launch the AP
sudo service isc-dhcp-server restart
#sudo hostapd -d /etc/hostapd/hostapd.conf
sudo service hostapd start
#sudo nmcli nm wifi on
#sudo service hostapd restart
