#!/bin/bash
set -e

# 加载环境变量
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup.sh"

LIB_NAME="libiconv-1.17"
LIB_URL="https://ftp.gnu.org/pub/gnu/libiconv/$LIB_NAME.tar.gz"
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

# 准备构建目录
rm -rf _build
mkdir _build && cd _build

echo "Configuring $LIB_NAME..."
../configure \
    --host=$TARGET_HOST \
    --prefix=$INSTALL_DIR \
    --enable-static \
    --disable-shared \
    --with-included-gettext=no \
    --with-libiconv-prefix=$INSTALL_DIR

echo "Building $LIB_NAME..."
make -j$(nproc)
make install

echo "$LIB_NAME built and installed to $INSTALL_DIR"
