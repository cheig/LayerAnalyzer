#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup_x86_64.sh"

cd "$SCRIPT_DIR/../external"

# ==================== 编译 pcre2 ====================
echo ""
echo ">>> 编译 pcre2..."
cd pcre2-10.42
rm -rf build-x86_64 && mkdir build-x86_64 && cd build-x86_64
cmake .. \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=x86_64 \
  -DANDROID_PLATFORM=android-$ANDROID_API \
  -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR \
  -DBUILD_SHARED_LIBS=OFF \
  -DPCRE2_BUILD_PCRE2GREP=OFF \
  -DPCRE2_BUILD_TESTS=OFF
make -j$(nproc)
make install
echo ">>> pcre2 编译完成"
cd ../..

# ==================== 编译 libiconv ====================
echo ""
echo ">>> 编译 libiconv..."
cd libiconv-1.17
make clean || true
./configure --host=$TARGET_HOST --prefix=$INSTALL_DIR --enable-static --disable-shared
make -j$(nproc)
make install
echo ">>> libiconv 编译完成"
cd ..

# ==================== 编译 libffi ====================
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
echo "验证编译结果 (x86_64 静态库)"
echo "========================================"
file $INSTALL_DIR/lib/*.a 2>/dev/null | grep -E "x86-64|x86_64" || echo "检查失败"

echo ""
echo ">>> 任务1 基础库编译完成!"
