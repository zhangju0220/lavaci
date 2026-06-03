#!/bin/bash

set -x

#准备环境
ip address
CLIENT_IP="10.0.0.40"
first_nic=$(ip -o link show up | awk -F': ' '!/lo/{print $2; exit}')
nmcli c a type Ethernet con-name $first_nic ifname $first_nic && nmcli c m $first_nic ipv4.address $CLIENT_IP/24 && nmcli c m $first_nic ipv4.method manual &&  nmcli c up $first_nic
ifconfig
lava-send client_ip ip=$CLIENT_IP

lava-wait server_done