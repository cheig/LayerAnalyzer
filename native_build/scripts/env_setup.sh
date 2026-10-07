#!/bin/bash

# ================= 配置区域 =================
# NDK 在 WSL2 下的路径 (推荐使用 Linux 版 NDK)
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/android-ndk-r27}"

# 目标架构配置
export ANDROID_API=26
export ARCH=aarch64
export TARGET_HOST=aarch64-linux-android
# 自动获取当前项目根目录 (假设脚本在 native_build/scripts 下)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
export INSTALL_DIR="$PROJECT_ROOT/native_build/output"

# NDK Toolchain 路径
export TOOLCHAIN=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin

# 将 Toolchain 添加到 PATH
export PATH=$TOOLCHAIN:$PATH

# ================= 编译器标志 =================
export CC=$TOOLCHAIN/${TARGET_HOST}${ANDROID_API}-clang
export CXX=$TOOLCHAIN/${TARGET_HOST}${ANDROID_API}-clang++
export AR=$TOOLCHAIN/llvm-ar
export AS=$TOOLCHAIN/llvm-as
export LD=$TOOLCHAIN/ld
export RANLIB=$TOOLCHAIN/llvm-ranlib
export STRIP=$TOOLCHAIN/llvm-strip
export NM=$TOOLCHAIN/llvm-nm

export CFLAGS="-fPIC -D__ANDROID_API__=$ANDROID_API -I$INSTALL_DIR/include"
export CXXFLAGS="-fPIC -D__ANDROID_API__=$ANDROID_API -I$INSTALL_DIR/include"
export LDFLAGS="-L$INSTALL_DIR/lib -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"
export PKG_CONFIG_PATH=$INSTALL_DIR/lib/pkgconfig
export PKG_CONFIG_LIBDIR=$INSTALL_DIR/lib/pkgconfig
export PKG_CONFIG_SYSROOT_DIR=/

echo "========================================"
echo "Environment Configured for LayerAnalyzer:"
echo "ANDROID_NDK_HOME: $ANDROID_NDK_HOME"
echo "INSTALL_DIR:      $INSTALL_DIR"
echo "CC:               $CC"
echo "========================================"
