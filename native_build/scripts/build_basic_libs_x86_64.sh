#!/bin/bash
set -e

# ===============================================================
# x86_64 基础库一键编译脚本
# 用途: 编译 zlib, pcre2, libiconv, libffi 为 x86_64 架构
# ===============================================================

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup_x86_64.sh"

# 创建输出目录
mkdir -p "$INSTALL_DIR/lib"
mkdir -p "$INSTALL_DIR/include"

cd "$SCRIPT_DIR/../external"

echo "========================================"
echo "开始编译 x86_64 基础库"
echo "输出目录: $INSTALL_DIR"
echo "========================================"

# ==================== 1. 编译 zlib ====================
echo ""
echo ">>> 编译 zlib..."
cd zlib-1.3.1
make clean || true
./configure --prefix=$INSTALL_DIR --static
make -j$(nproc)
make install
echo ">>> zlib 编译完成"
cd ..

# ==================== 2. 编译 pcre2 ====================
echo ""
echo ">>> 编译 pcre2..."
cd pcre2-10.42
rm -rf build-x86_64 && mkdir build-x86_64 && cd build-x86_64
cmake .. \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=x86_64 \
  -DANDROID_PLATFORM=android-$ANDROID_API \
  -DCMAKE_POLICY_DEFAULT_CMP0057=NEW \
  -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR \
  -DBUILD_SHARED_LIBS=OFF \
  -DPCRE2_BUILD_PCRE2GREP=OFF \
  -DPCRE2_BUILD_TESTS=OFF
make -j$(nproc)
make install
echo ">>> pcre2 编译完成"
cd ../..

# ==================== 3. 编译 libiconv ====================
echo ""
echo ">>> 编译 libiconv..."
cd libiconv-1.17
make clean || true
./configure --host=$TARGET_HOST --prefix=$INSTALL_DIR --enable-static --disable-shared
make -j$(nproc)
make install
echo ">>> libiconv 编译完成"
cd ..

# ==================== 4. 编译 libffi ====================
echo ""
echo ">>> 编译 libffi..."
cd libffi-3.4.6
make clean || true
./configure --host=$TARGET_HOST --prefix=$INSTALL_DIR --enable-static --disable-shared
make -j$(nproc)
make install
echo ">>> libffi 编译完成"
cd ..

# ==================== 验证 ====================
echo ""
echo "========================================"
echo "验证编译结果"
echo "========================================"
echo "静态库:"
file $INSTALL_DIR/lib/*.a 2>/dev/null | grep -E "x86-64|x86_64" || echo "未找到静态库"
echo ""
echo "头文件目录:"
ls -la $INSTALL_DIR/include/ | head -20

echo ""
echo "========================================"
echo "x86_64 基础库编译完成!"
echo "========================================"
