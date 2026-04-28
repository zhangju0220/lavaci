#!/bin/bash

set -x

OUTPUT="$(pwd)/output"
mkdir -p "$OUTPUT"
RESULT_FILE="${OUTPUT}/result.txt"

#环境准备

SERVER_IP="10.0.0.2"
nmcli c a type Ethernet con-name eth0 ifname eth0 && nmcli c m eth0 ipv4.address $SERVER_IP/24 && nmcli c m eth0 ipv4.method manual &&  nmcli c up eth0
lava-wait client_ip
TARGET=$(grep -oP 'ip=\K[^ ]+' /tmp/lava_multi_node_cache.txt)
ping -c 4 $TARGET

# 安装测试工具
which nmap || dnf install -y nmap


#扫描开放端口
nmap -sS -sV -p- --open $TARGET -oN port_scan.txt
OPEN_PORTS=$(grep "^[0-9]*/tcp" port_scan.txt | awk '{print $1}' | cut -d/ -f1)

#判断暴露的端口是否存在风险
for port in $OPEN_PORTS; do
  #若暴露22端口，检查ssh配置
  if [ "$port" = "22" ]; then
    nmap -sS -p $port --script ssh-auth-methods,ssh2-enum-algos,sshv1 $TARGET -oN ssh_scan.txt
    # Password authentication检查：是否允许密码登录
    if grep "password" ssh_scan.txt; then
      # 检查密码认证
      if grep -Ei "^\s*PasswordAuthentication\s+no" /etc/ssh/sshd_config; then
        echo "ssh_password_authentication pass" >> $RESULT_FILE
      else
        echo "ssh_password_authentication fail" >> $RESULT_FILE
      fi
      # 检查 root 登录
      if grep -Ei "^\s*PermitRootLogin\s+(yes|without-password|prohibit-password)" /etc/ssh/sshd_config; then
        echo "ssh_root_login fail" >> $RESULT_FILE
      else
        echo "ssh_root_login pass" >> $RESULT_FILE
      fi
    fi

    # Weak algorithms检查：是否存在ssh弱算法
    if grep -Ei 'diffie-hellman-group1|diffie-hellman-group14-sha1|ssh-rsa|arcfour|3des-cbc|aes.*cbc|hmac-md5|hmac-sha1-96|umac-64' ssh_scan.txt; then
      echo "ssh_weak_algorithms fail" >> $RESULT_FILE
    else
      echo "ssh_weak_algorithms pass" >> $RESULT_FILE
    fi

    # sshv1检查：是否存在sshv1协议
    if grep -i 'supports sshv1' ssh_scan.txt; then
      echo "sshv1 fail" >> $RESULT_FILE
    else
      echo "sshv1 pass" >> $RESULT_FILE
    fi

  #若暴露111端口，检查nfs服务
  elif [ "$port" = "111" ]; then
    nmap -p $port --script rpcinfo $TARGET -oN rpc_scan.txt
    if grep -q "nfs" rpc_scan.txt; then
      echo "rpc_nfs_exposed fail" >> $RESULT_FILE
    else
      echo "rpc_nfs_exposed pass" >> $RESULT_FILE
    fi
  fi
done

lava-send server_done
