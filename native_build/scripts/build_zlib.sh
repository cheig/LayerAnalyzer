#!/bin/bash
set -e

# 加载环境变量
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup.sh"

LIB_NAME="zlib-1.3.1"
LIB_URL="https://www.zlib.net/$LIB_NAME.tar.gz"
WORK_DIR="$PROJECT_ROOT/native_build/external"

cd "$WORK_DIR"

# 下载与解压
if [ ! -d "$LIB_NAME" ]; then
    if [ ! -f "$LIB_NAME.tar.gz" ]; then
        echo "Downloading $LIB_NAME..."
        wget "$LIB_URL"
    fi
    tar -xf "$LIB_NAME.tar.gz"
fi

cd "$LIB_NAME"

# zlib 不建议在子目录编译
echo "Configuring $LIB_NAME..."
# zlib 的 configure 不支持 --host，它会直接读取环境变量 CC, AR, RANLIB
# 我们已经在 env_setup.sh 中设置好了
./configure --static --prefix=$INSTALL_DIR

echo "Building $LIB_NAME..."
make -j$(nproc)
make install

echo "$LIB_NAME built and installed to $INSTALL_DIR"
