#!/usr/bin/bash

# Install dependencies
sudo apt-get install hostapd isc-dhcp-server

# Configure dhcp server
if ! grep -q "subnet 10.0.0.0 netmask 255.255.255.0 {
option routers 10.0.0.1;
option domain-name-servers 8.8.8.8, 8.8.4.4, 208.67.222.222;
range 10.0.0.2 10.0.0.16;
}" /etc/dhcp/dhcpd.conf ; then
sudo sh -c "echo 'subnet 10.0.0.0 netmask 255.255.255.0 {
option routers 10.0.0.1;
option domain-name-servers 8.8.8.8, 8.8.4.4, 208.67.222.222;
range 10.0.0.2 10.0.0.16;
}' >> /etc/dhcp/dhcpd.conf"
fi

# Allow dhcp server to run for our ap iface
if grep -q "INTERFACES=" /etc/default/isc-dhcp-server ; then
	sudo sed -i '/INTERFACES=/d' /etc/default/isc-dhcp-server
fi
sudo sh -c "echo 'INTERFACES=\"$1\"' >> /etc/default/isc-dhcp-server"

# Configure static IP for the AP
if ! grep -q "auto $1
iface $1 inet static
address 10.0.0.1
netmask 255.255.255.0" /etc/network/interfaces ; then
sudo sh -c "echo 'auto $1
iface $1 inet static
address 10.0.0.1
netmask 255.255.255.0' >> /etc/network/interfaces"
fi

# Configure hostapd
if [ -f /etc/hostapd/hostapd.conf ]; then # if config exists, remove
	sudo rm /etc/hostapd/hostapd.conf
fi
sudo touch /etc/hostapd/hostapd.conf # start from scratch config
sudo sh -c "echo 'interface=$1
driver=nl80211
ssid=BlueAP
hw_mode=g
channel=11' >> /etc/hostapd/hostapd.conf"

# Configure the hostapd daemon
if grep -q "DAEMON_CONF=" /etc/default/hostapd ; then
	sudo sed -i '/DAEMON_CONF=/d' /etc/default/hostapd
fi
sudo sh -c "echo 'DAEMON_CONF=\"/etc/hostapd/hostapd.conf\"' >> /etc/default/hostapd"

# Restart the DHCP server and route interface
sudo nmcli nm wifi off
sudo rfkill unblock wlan
sudo ifconfig $1 10.0.0.1 netmask 255.255.255.0 up # Init the interface
sleep 2
sudo /etc/init.d/isc-dhcp-server restart # Restart dhcp server
sudo sysctl -w net.ipv4.ip_forward=1 # Allow IP forwarding
sudo iptables -t nat -A POSTROUTING -o $2 -j MASQUERADE # Routing rules
sudo iptables -D FORWARD -i $1 -s 10.0.0.0/16 -j ACCEPT # Deletes if exists
sudo iptables -D FORWARD -i $2 -d 10.0.0.0/16 -j ACCEPT # Crazy redundant, but prevents duplicates from building up
sudo iptables -A FORWARD -i $1 -s 10.0.0.0/16 -j ACCEPT # Re-add
sudo iptables -A FORWARD -i $2 -d 10.0.0.0/16 -j ACCEPT

# Finally, launch the AP
#sudo hostapd -d /etc/hostapd/hostapd.conf
sudo service hostapd start
sudo nmcli nm wifi on
sudo service hostapd restart
