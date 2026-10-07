#!/bin/bash
set -e

# 加载环境变量
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup.sh"

LIB_NAME="libffi-3.4.6"
LIB_URL="https://github.com/libffi/libffi/releases/download/v3.4.6/$LIB_NAME.tar.gz"
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
    --disable-docs

echo "Building $LIB_NAME..."
make -j$(nproc)
make install

# 优化：处理 libffi 头文件路径问题
if [ -d "$INSTALL_DIR/lib/$LIB_NAME/include" ]; then
    echo "Syncing libffi headers to $INSTALL_DIR/include..."
    cp -r $INSTALL_DIR/lib/$LIB_NAME/include/* $INSTALL_DIR/include/
fi

echo "$LIB_NAME built and installed to $INSTALL_DIR"
