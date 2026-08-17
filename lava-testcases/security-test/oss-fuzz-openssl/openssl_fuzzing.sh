#!/bin/bash
set -x

OUTPUT="$(pwd)/output"
mkdir -p "$OUTPUT"
RESULT_FILE="${OUTPUT}/result.txt"
WORKSPACE=$(pwd)

FUZZTIME="${1}"
MAILBOX="${2}"

# 加载数据盘
load_disk(){
  DISK=/dev/vdb
  PART=${DISK}1
  MNT=/build

  # 1. 分区并格式化
  parted -s $DISK mklabel gpt
  parted -s $DISK mkpart primary ext4 0% 100%
  mkfs.ext4 -F $PART

  # 2. 挂载并写入fstab（重启生效）
  mkdir -p $MNT
  UUID=$(blkid -s UUID -o value $PART)
  echo "UUID=$UUID $MNT ext4 defaults,noatime 0 2" >> /etc/fstab
  mount -a

  # 3. 验证
  df -h $MNT
}


#测试环境准备
env_prep(){
  cd /root/

  dnf makecache
  dnf -y install rpm-build docker-engine git

  #开启docker experimental功能
  touch /etc/docker/daemon.json
  mkdir -p /build/docker   #设置docker存放路径
  cat > /etc/docker/daemon.json << 'EOF'
{
  "experimental": true,
  "data-root":"/build/docker"
}
EOF
  systemctl restart docker
  docker info | grep -i 'experimental'

  #设置rpm打包环境
  dnf -y install rpmdevtools
  rpmdev-setuptree    #自动在用户家目录生成一个rpmbuild的文件夹，

  #下载oss-fuzz仓库并进行rv环境兼容
  git clone https://github.com/google/oss-fuzz.git
  #1.infra/constants.py文件ARCHITECTURES增加riscv64架构兼容
  sed -i "s/ARCHITECTURES = \['i386', 'x86_64', 'aarch64'\]/ARCHITECTURES = ['i386', 'x86_64', 'aarch64', 'riscv64']/" oss-fuzz/infra/constants.py
  #2.infra/helper.py文件platform 增加riscv64架构兼容
  old="platform = 'linux/arm64' if architecture == 'aarch64' else 'linux/amd64'"
  new="platform = 'linux/arm64' if architecture == 'aarch64' else 'linux/riscv64' if architecture == 'riscv64' else 'linux/amd64'"
  sed -i "s|$old|$new|g" oss-fuzz/infra/helper.py
}

#测试数据准备
data_prep(){
  #根据openEuler系统版本下载对应的的openssl源码，并将安装了补丁的源码文件放到oss-fuzz框架openssl目录下
  #source /etc/os-release
  #BRANCH="${NAME}-${VERSION_ID}-$(echo "$VERSION" | sed 's/.*(\(.*\))/\1/')"
  #git clone --branch $BRANCH https://atomgit.com/src-openeuler/openssl
  VER=$(rpm -q openssl --qf '%{VERSION}')
  REL=$(rpm -q openssl --qf '%{RELEASE}')
  echo "${VER}-${REL}"

  dnf download --source openssl-${VER}-${REL}
  mkdir openssl && cd openssl
  rpm2cpio /root/openssl-*.src.rpm | cpio -idmv

  cp -r ./* /root/rpmbuild/SOURCES
  cd /root/rpmbuild/SOURCES
  dnf builddep openssl.spec -y #下载编译依赖
  rpmbuild -bp openssl.spec
  cd /root/rpmbuild/BUILD
  cp -r openssl-*/ /root/oss-fuzz/projects/openssl
}

#执行测试
fuzz_test(){
  cd /root/oss-fuzz
  #下载适用于rv环境的基础镜像
  docker pull zhangzhang1/oss-fuzz-base-image:latest
  docker pull zhangzhang1/oss-fuzz-base-clang:latest
  docker pull zhangzhang1/oss-fuzz-base-builder:latest
  docker pull zhangzhang1/oss-fuzz-base-runner:latest
  docker pull zhangzhang1/oss-fuzz-base-runner-debug:latest

  docker tag zhangzhang1/oss-fuzz-base-image gcr.io/oss-fuzz-base/base-image
  docker tag zhangzhang1/oss-fuzz-base-clang gcr.io/oss-fuzz-base/base-clang
  docker tag zhangzhang1/oss-fuzz-base-builder gcr.io/oss-fuzz-base/base-builder
  docker tag zhangzhang1/oss-fuzz-base-runner gcr.io/oss-fuzz-base/base-runner
  docker tag zhangzhang1/oss-fuzz-base-runner-debug gcr.io/oss-fuzz-base/base-runner-debug


  #设置oss-fuzz中openssl项目Dockerfile,同时调整build.sh文件
  PROJECT_PATH="projects/openssl"
  cp projects/openssl/Dockerfile projects/openssl/Dockerfile.bak
  # 获取系统中openssl软件包版本
  OPENSSL_DIR=$(basename projects/openssl/openssl-*)
  BRANCH=$(echo "$OPENSSL_DIR" | sed 's/openssl-\([0-9]*\)\.\([0-9]*\).*/\1.\2/')
  VERSION=$(echo "$OPENSSL_DIR" | sed 's/openssl-\([0-9]*\)\.\([0-9]*\).*/\1\2/')
  OPENSSL_TARGET=openssl$VERSION
  cat > projects/openssl/Dockerfile << 'EOF'
FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make
RUN git clone --depth 1 --branch openssl-BRANCH https://atomgit.com/openssl/openssl.git OPENSSL_TARGET
COPY OPENSSL_DIR $SRC/OPENSSL_TARGET
RUN cd $SRC/OPENSSL_TARGET/ && git submodule update --init fuzz/corpora
WORKDIR openssl
COPY build.sh *.options replay_build.sh run_tests.sh $SRC/
ENV AFL_SKIP_OSSFUZZ=1
ENV AFL_LLVM_MODE_WORKAROUND=0
EOF
  sed -i "s|BRANCH|$BRANCH|g" projects/openssl/Dockerfile
  sed -i "s|OPENSSL_DIR|$OPENSSL_DIR|g" projects/openssl/Dockerfile
  sed -i "s|OPENSSL_TARGET|$OPENSSL_TARGET|g" projects/openssl/Dockerfile

  BUILDSH='projects/openssl/build.sh'
  sed -i '/^cd \$SRC\/openssl\//,$ d' $BUILDSH
  echo '
# In introspector, indexer builds and when capturing replay builds, only build
# the master branch
if [[ "$SANITIZER" == introspector || -n "${INDEXER_BUILD:-}" || -n "${CAPTURE_REPLAY_SCRIPT:-}" ]]; then
  exit 0
fi
' >> $BUILDSH

  if [ $VERSION = '30' ]; then
    echo '
cd $SRC/openssl$VERSION/
build_fuzzers "_$VERSION" "" "engines"
' >> $BUILDSH
 else
    echo '
cd $SRC/openssl$VERSION/
build_fuzzers "_$VERSION" "no-apps no-docs" "engines"
' >> $BUILDSH
  fi

  sed -i "s|\$VERSION|$VERSION|g" $BUILDSH

  # 构建fuzz target
  python3 infra/helper.py build_fuzzers --architecture riscv64 --sanitizer undefined openssl

  # 执行fuzz
  target=$(basename -a build/out/openssl/*30)
  for targ in $target; do
    python3 infra/helper.py run_fuzzer --architecture riscv64 --sanitizer undefined openssl $targ -- -max_total_time=$FUZZTIME -timeout=60
  done

}

#通过邮件发送附件
send_main(){
  local crash_zip="$1" #crash压缩文件
  dnf install -y postfix mutt
  postconf -e "message_size_limit = 52428800"
  systemctl reload postfix
  echo "fuzzing crashes" | mutt -s "openssl fuzzing" -a $crash_zip -- $MAILBOX
  tail -100 /var/log/maillog | grep -i "$MAILBOX"
}

#输出测试结果
data_to_lava(){
  # openssl fuzzing：全部通过输出openssl-fuzzing pass，否则输出 fuzz-target + fail
  # 返回测试路径
  cd $WORKSPACE
  OUTPUTDIR=$(find /root/oss-fuzz/build/out/openssl -maxdepth 1 -type d -name '*address_out')
  FAIL=0
  CRASHDIR=''
  for dir in $OUTPUTDIR; do
    if [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
      FAIL=1
      #记录有crashes的目录
      CRASHDIR="${CRASHDIR:+$CRASHDIR }$dir"
    fi
  done
  if [ $FAIL = 0 ];then
    echo 'openssl-fuzzing pass' >> $RESULT_FILE
  else
    echo 'openssl-fuzzing fail' >> $RESULT_FILE
  fi
  #
  if [ -z "$CRASHDIR" ]; then
    echo "模糊测试完成，无crash"
  else
    echo "模糊测试完成，"
    zip -r openssl-crash.zip $CRASHDIR
    send_main openssl-crash.zip
  fi


}

#qemu环境加载数据盘
if [ "$(systemd-detect-virt)" = "qemu" ]; then
  load_disk
fi
# 测试环境准备
env_prep
# 测试数据准备
data_prep
#执行fuzz测试
fuzz_test
#输出测试结果
data_to_lava


