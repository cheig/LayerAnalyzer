#!/bin/bash
set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup.sh"

CARES_VER="1.34.4"
URL="https://c-ares.org/download/c-ares-${CARES_VER}.tar.gz"
EXT_DIR="$PROJECT_ROOT/native_build/external"

mkdir -p "$EXT_DIR"
cd "$EXT_DIR"

echo "[INFO] Cloning c-ares $CARES_VER..."
if [ ! -d "c-ares-$CARES_VER" ]; then
    git clone --depth 1 --branch "v$CARES_VER" https://github.com/c-ares/c-ares.git "c-ares-$CARES_VER"
fi
cd "c-ares-$CARES_VER"

mkdir -p build-android
cd build-android

cmake -G "Ninja" \
    -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="arm64-v8a" \
    -DANDROID_PLATFORM="android-$ANDROID_API" \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_SHARED_LINKER_FLAGS="-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384" \
    -DCARES_STATIC=OFF \
    -DCARES_SHARED=ON \
    -DCARES_INSTALL=ON \
    ..

ninja
ninja install
