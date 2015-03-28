Instructions for intercepting packets via TAP interface
================================================================

Note that setting up the device may require root priveleges, as well as accessing it.

1. run the mktap.sh script to create interface and assign an IP address

$ sudo mktap.sh

2. compile tuntap_sniff.c (TODO: integrate into makefile)

$ gcc -Wall tuntap_sniff.c -o tuntap_sniff

3. run tuntap_sniff to start reading packets from TUNTAP device and log packets to log.txt

$ sudo ./tuntap

