# BlueVirtualAP
The goal of this application is to create a Virtual Access Point that shares an existing network interface.
For example, a wireless signal is captured on the network card, and the same network card will then be used to broadcast a VAP.

To spawn the access point, you'll need root privileges.

	sudo bash ./mkvap.sh <ap iface> <inet iface>

For example, if you wanted to share the internet from eth0 to wlan0 you would run:
	sudo bash ./mkvap.sh wlan0 eth0
