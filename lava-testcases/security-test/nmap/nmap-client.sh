#!/bin/bash

set -x

OUTPUT="$(pwd)/output"
mkdir -p "$OUTPUT"
RESULT_FILE="${OUTPUT}/result.txt"
#准备环境
ip address
CLIENT_IP="10.0.0.3"
nmcli c a type Ethernet con-name eth0 ifname eth0 && nmcli c m eth0 ipv4.address $CLIENT_IP/24 && nmcli c m eth0 ipv4.method manual &&  nmcli c up eth0
ifconfig
lava-send client_ip ip=$CLIENT_IP

lava-wait server_done