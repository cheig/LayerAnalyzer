#!/bin/bash

# ================= x86_64 配置区域 =================
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/android-ndk-r27}"
export ANDROID_API=26
export ARCH=x86_64
export TARGET_HOST=x86_64-linux-android

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
export INSTALL_DIR="$PROJECT_ROOT/native_build/output_x86_64"

export TOOLCHAIN=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin
export PATH=$TOOLCHAIN:$PATH

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

echo "Environment Configured for x86_64"
echo "CC: $CC"
echo "INSTALL_DIR: $INSTALL_DIR"
