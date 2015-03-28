#!/usr/bin/bash

ip tuntap add tap0 mode tap
ip addr add 192.168.5.10/24 dev tap0 # TODO get IP from args
ip link set tap0 up
echo "interface tap0 created"
