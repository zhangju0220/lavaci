#!/bin/bash

set -x


OUTPUT="$(pwd)/output"
PWD="$(pwd)"
mkdir -p "$OUTPUT"
RESULT_FILE="${OUTPUT}/result.txt"


check_result(){

  CRASH_DIR="$WORKDIR/crashes"
    # 1. 判定: WORKDIR 下不存在 crashes 文件夹 -> PASS
  if [ ! -d "$CRASH_DIR" ]; then
      echo "kernel_syzkaller" "pass" >> $RESULT_FILE
  else
    # 2 & 3. 遍历 crashes 目录，区分内核问题与非内核问题
    KERNEL_CRASH_COUNT=0
    NON_KERNEL_CRASH_COUNT=0
    KERNEL_BUG_LIST=""

    # 匹配非内核问题的正则表达式 (可根据实际日志持续补充)
    NON_KERNEL_PATTERN="lost connection|no output from test machine|timed out|ssh.*failed|executor.*not responding|qemu.*exited|out of memory|oom-killer.*syz"

    for bug_dir in "$CRASH_DIR"/*/; do
        # 跳过空目录或非目录项
        [ ! -d "$bug_dir" ] && continue

        DESC_FILE="${bug_dir}description"
        BUG_HASH=$(basename "$bug_dir")

        # 如果连 description 都没有，视为不完整/环境问题
        if [ ! -f "$DESC_FILE" ]; then
            NON_KERNEL_CRASH_COUNT=$((NON_KERNEL_CRASH_COUNT + 1))
            continue
        fi

        DESCRIPTION=$(cat "$DESC_FILE")

        # 使用大小写不敏感匹配判断是否为非内核问题
        if echo "$DESCRIPTION" | grep -qiE "$NON_KERNEL_PATTERN"; then
            NON_KERNEL_CRASH_COUNT=$((NON_KERNEL_CRASH_COUNT + 1))
        else
            KERNEL_CRASH_COUNT=$((KERNEL_CRASH_COUNT + 1))
            # 记录真实内核 Bug 信息供 LAVA 日志采集
            HAS_REPRO="NO"
            [ -f "${bug_dir}repro.c" ] && HAS_REPRO="YES"
            KERNEL_BUG_LIST="${KERNEL_BUG_LIST}\n  - [${BUG_HASH:0:8}] $DESCRIPTION (Repro: $HAS_REPRO)"
        fi
    done

    # ==========================================
    # 输出摘要与最终判定
    # ==========================================
    echo "=== Syzkaller Result Summary ==="
    echo "Total crash entries: $((KERNEL_CRASH_COUNT + NON_KERNEL_CRASH_COUNT))"
    echo "Kernel bugs found:   $KERNEL_CRASH_COUNT"
    echo "Non-kernel issues:   $NON_KERNEL_CRASH_COUNT"

    if [ "$KERNEL_CRASH_COUNT" -gt 0 ]; then
        echo "kernel_syzkaller" "fail" >> $RESULT_FILE
    else
        echo "kernel_syzkaller" "pass" >> $RESULT_FILE
    fi
  fi
}

#设置server端网络，并获取client ip地址
SERVER_IP="10.0.0.30"
first_nic=$(ip -o link show up | awk -F': ' '!/lo/{print $2; exit}')
nmcli c a type Ethernet con-name $first_nic ifname $first_nic && nmcli c m $first_nic ipv4.address $SERVER_IP/24 && nmcli c m $first_nic ipv4.method manual &&  nmcli c up $first_nic
lava-wait client_ip
CLIENTIP=$(grep -oP 'ip=\K[^ ]+' /tmp/lava_multi_node_cache.txt)
ping -c 4 $CLIENTIP
ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N ""  #生成公钥对
# 添加client端秘钥登录,同时调整ssh配置
commands="sed -i '/AllowTcpForwarding/d' /etc/ssh/sshd_config
sed -i '/GatewayPorts/d' /etc/ssh/sshd_config
echo 'AllowTcpForwarding yes' >> /etc/ssh/sshd_config
echo 'GatewayPorts yes' >> /etc/ssh/sshd_config
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys"
dnf install -y sshpass
sshpass -p 'openEuler12#$' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "/root/.ssh/id_rsa.pub" root@"$CLIENTIP":/root/.ssh/authorized_keys
sshpass -p 'openEuler12#$' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 root@"$CLIENTIP" "$commands"


cd /root
#检查内核是否满足测试要求
zcat /proc/config.gz | grep -E "BINFMT_MISC|KCOV|VIRTIO_BLK|SELINUX|KASAN"

#下载kernel-debuginfo软件包,获取vmlinux
: <<'COMMENT'
REPO_FILE="/etc/yum.repos.d/openEuler.repo"
BASEURL=$(awk -v arch="$(uname -m)" '
    /^\[debuginfo\]/ { found=1; next }
    /^\[/             { found=0 }
    found && /^baseurl=/ {
        sub(/^baseurl=[ \t]*/, "")
        gsub(/\$basearch|\$\{basearch\}/, arch)
        print
        exit
    }
' "$REPO_FILE")
wget $BASEURL/Packages/kernel-debuginfo-$(uname -r).rpm
rpm2cpio kernel-debuginfo-*.rpm | cpio -idmv ./usr/lib/debug/lib/modules/*/vmlinux
COMMENT

wget http://10.20.237.128:7777/vmlinux

# 编译syzkaller
dnf install -y gcc gcc-c++ make cmake automake autoconf git gdb glibc-devel libstdc++-devel binutils patch diffutils pkgconf libstdc++-static go
: << 'content'
git clone https://github.com/google/syzkaller.git
cd syzkaller
make TARGETOS=linux TARGETARCH=riscv64 -j$(nproc)
content
wget http://10.20.237.128:7777/syzkaller.zip
unzip syzkaller.zip
cd syzkaller

# 执行fuzzing
WORKDIR="/root/syzkaller/workdir"
#KERNEL="/root/usr/lib/debug/lib/modules/$(uname -r)"
KERNEL="/root"
cat > config.json << EOF
{
    "target": "linux/riscv64",
    "http": "0.0.0.0:61952",
    "rpc": "0.0.0.0:0",
    "workdir": "$WORKDIR",
    "kernel_obj": "$KERNEL",
    "syzkaller": "/root/syzkaller",
    "sshkey": "/root/.ssh/id_rsa",
    "procs": 1,
    "type": "isolated",
    "vm": {
        "targets": ["$CLIENTIP"],
        "target_dir": "/root/syzkaller",
        "pstore": false,
        "target_reboot": true
    }
}
EOF
#减少并发防止oom
export SYZ_ADDR2LINE_PARALLEL=1   # 限制为1个并发
export SYZ_ADDR2LINE_BATCH=1000   # 每批处理更多地址，减少进程启动次数
timeout 36000 /root/syzkaller/bin/syz-manager --config=/root/syzkaller/config.json

cd $PWD
check_result


lava-send server_done











