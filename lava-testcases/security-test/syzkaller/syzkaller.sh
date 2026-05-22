#!/bin/bash

set -x


OUTPUT="$(pwd)/output"
mkdir -p "$OUTPUT"
RESULT_FILE="${OUTPUT}/result.txt"
LAVA_WORKDIR="$(pwd)"

mkdir -p /build
KERNEL_SRC=/usr/src/linux-6.6.0-138.0.0.121.oe2403sp3.riscv64
KERNEL_DEST=/build/linux-build
mkdir -p $KERNEL_DEST
ROOTFS_DIR=/build/rootfs
mkdir -p $ROOTFS_DIR
SYZ_WORKDIR="/build/syzkaller"


make_kernel(){
  dnf install -y kernel-source
  cd $KERNEL_SRC
  dnf install -y gcc make flex bison openssl-devel elfutils-libelf-devel \
               perl python3 bc dwarves cpio gzip tar xz util-linux
  make ARCH=riscv -C $KERNEL_SRC mrproper
  # 生成默认配置
  zcat /proc/config.gz > $KERNEL_DEST/.config
  FILE="$KERNEL_SRC/drivers/acpi/pci_mcfg.c"

  sed -i \
	      -e 's/^#ifdef CONFIG_RISCV$/#ifdef CONFIG_PCIE_DW_SOPHGO/' \
	          -e 's|^#endif /\* RISCV \*/$|#endif /* CONFIG_PCIE_DW_SOPHGO */|' \
		      "$FILE"

  # 脚本路径指向源码目录，并操作/build/linux-build目录下的 .config
  $KERNEL_SRC/scripts/config --file $KERNEL_DEST/.config --enable KCOV
  $KERNEL_SRC/scripts/config --file $KERNEL_DEST/.config --enable DEBUG_FS
  $KERNEL_SRC/scripts/config --file $KERNEL_DEST/.config --enable KASAN
  $KERNEL_SRC/scripts/config --file $KERNEL_DEST/.config --enable UBSAN
  $KERNEL_SRC/scripts/config --file $KERNEL_DEST/.config --enable KASAN_INLINE
  $KERNEL_SRC/scripts/config --file $KERNEL_DEST/.config --enable DEBUG_INFO
  $KERNEL_SRC/scripts/config --file $KERNEL_DEST/.config --enable DEBUG_INFO_DWARF4
  $KERNEL_SRC/scripts/config --file $KERNEL_DEST/.config --enable NAMESPACES
  $KERNEL_SRC/scripts/config --file $KERNEL_DEST/.config --enable NET_NS
  $KERNEL_SRC/scripts/config --file $KERNEL_DEST/.config --module KVM

  # 修改完成后更新配置
  make ARCH=riscv -C $KERNEL_SRC O=$KERNEL_DEST olddefconfig
  # 编译
  make ARCH=riscv -C $KERNEL_SRC O=$KERNEL_DEST -j$(nproc) Image vmlinux
}

del_rootfs(){
  cd $ROOTFS_DIR
  df -h
  lsblk
  free -h
  wget https://fast-mirror.isrc.ac.cn/openeuler-sig-riscv/openEuler-RISC-V/RVCK/openEuler24.03-LTS-SP3/openeuler-rootfs.img.zst
  unzstd openeuler-rootfs.img.zst
  ls $ROOTFS_DIR/openeuler-rootfs.img
  mkdir -p $ROOTFS_DIR/mount/
  mount -o loop $ROOTFS_DIR/openeuler-rootfs.img $ROOTFS_DIR/mount

  echo "=== 配置 SSH ==="
  # 生成密钥对（如果不存在）
  if [ ! -f /root/.ssh/id_rsa ]; then
      mkdir -p /root/.ssh
      ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N ""
  fi

  # 确保 rootfs 中有 .ssh 目录
  mkdir -p $MOUNT_POINT/root/.ssh

  # 写入公钥
  cat /root/.ssh/id_rsa.pub >> $MOUNT_POINT/root/.ssh/authorized_keys
  chmod 700 $MOUNT_POINT/root/.ssh
  chmod 600 $MOUNT_POINT/root/.ssh/authorized_keys

  # 配置 sshd_config
  cat > $MOUNT_POINT/etc/ssh/sshd_config << 'EOF'
# Syzkaller 最小化 SSH 配置
Port 22
ListenAddress 0.0.0.0
PermitRootLogin yes
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
UseDNS no
GSSAPIAuthentication no
AllowUsers root

# Syzkaller 必需：端口转发
AllowTcpForwarding yes
GatewayPorts yes

# 性能优化
MaxSessions 100
MaxStartups 100:30:200
LoginGraceTime 0
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3

PidFile /var/run/sshd.pid
EOF
}

make_syzkaller(){
  cd /build
  dnf install -y gcc gcc-c++ make cmake automake autoconf git gdb glibc-devel libstdc++-devel binutils patch diffutils pkgconf libstdc++-static go
  git clone https://github.com/google/syzkaller.git
  cd syzkaller
  sed -i 's/time.Minute\*inst.timeouts.Scale/time.Minute*90*inst.timeouts.Scale/g' vm/qemu/qemu.go
  export GOPROXY=https://goproxy.cn,https://mirrors.aliyun.com/goproxy/,direct # 添加代理，加速下载
  make TARGETOS=linux TARGETARCH=riscv64 -j$(nproc)
  ls ./bin/syz-manager ./bin/linux_riscv64/syz-executor
}

qemu_prep(){
  #安装qemu
  dnf install -y qemu-system-riscv
}

syzkaller_fuzzing(){
  cd $SYZ_WORKDIR
  CRASH_WORKDIR="$SYZ_WORKDIR/workdir"
  mkdir $CRASH_WORKDIR
  cat >> config.json << EOF
{
    "name": "riscv64-qemu",
    "target": "linux/riscv64",
    "http": "0.0.0.0:61952",
    "rpc": "0.0.0.0:42173",
    "workdir": "$CRASH_WORKDIR",
    "kernel_obj": "$KERNEL_DEST",
    "sshkey": "/root/.ssh/id_rsa",
    "ssh_user": "root",
    "image": "$ROOTFS_DIR/openeuler-rootfs.img",
    "syzkaller": "/build/syzkaller",
    "type": "qemu",
    "vm": {
        "count": 1,
        "cpu": 4,
        "mem": 4096,
        "kernel": "$KERNEL_DEST/arch/riscv/boot/Image",
        "cmdline": "build=/dev/vda rw console=ttyS0 earlycon=sbi selinux=0",
        "qemu_args": "-machine virt",
        "snapshot": true
    }
}
EOF
  timeout 3600 ./bin/syz-manager --config=config.json
}

check_result(){
  # 1. 判定: WORKDIR 下不存在 crashes 文件夹 -> PASS
  CRASH_DIR="$CRASH_WORKDIR/crashes"
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

echo "开启CONFIG_KCOV、CONFIG_KASAN等配置项并编译内核"
#make_kernel

mkdir -p $KERNEL_DEST/arch/riscv/boot
wget http://10.211.102.58/kernel-build-results/rvck-olk_pr_68/Image  -O $KERNEL_DEST/arch/riscv/boot/Image  # ← LAVA 自动下载此内核
wget http://10.20.237.128:7777/vmlinux -O $KERNEL_DEST/vmlinux
echo "编译syzkaller"
make_syzkaller
#dnf install -y gcc gcc-c++ make cmake automake autoconf git gdb glibc-devel libstdc++-devel binutils patch diffutils pkgconf libstdc++-static go

#wget http://10.20.237.128:7777/syzkaller.zip -O /build/syzkaller.zip
#cd /build
#unzip syzkaller.zip


echo "开启系统免密登录及端口转发功能"
del_rootfs

echo "为测试环境准备qemu"
qemu_prep

echo "执行syzkaller fuzzing"
syzkaller_fuzzing

echo "输出lava格式结果"
cd $LAVA_WORKDIR
check_result












