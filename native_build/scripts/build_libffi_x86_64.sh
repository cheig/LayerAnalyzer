#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup_x86_64.sh"

cd "$SCRIPT_DIR/../external/libffi-3.4.6"

echo ">>> 编译 libffi for x86_64..."

# 清理旧构建
rm -rf x86_64-pc-linux-android _build_x86_64 || true

# 在单独的构建目录中编译
mkdir -p _build_x86_64
cd _build_x86_64

../configure \
  --host=$TARGET_HOST \
  --prefix=$INSTALL_DIR \
  --enable-static \
  --disable-shared

make -j$(nproc)
make install

echo ">>> libffi 编译完成"

# 验证
echo ""
echo "验证 libffi:"
file $INSTALL_DIR/lib/libffi.a | grep -E "x86-64|x86_64" && echo "OK"
