#!/bin/bash
set -e

# 加载环境变量
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup.sh"

# 添加 16 KB 对齐链接器标志
export LDFLAGS="$LDFLAGS -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"

echo "========================================="
echo "[最终方案] 使用 Wireshark 4.0.10 重新编译"
echo "========================================="

# 使用之前成功编译的版本
WIRESHARK_VER="4.0.10"
WIRESHARK_SRC="$PROJECT_ROOT/native_build/external/wireshark-$WIRESHARK_VER"

if [ ! -d "$WIRESHARK_SRC" ]; then
    echo "错误: Wireshark $WIRESHARK_VER 源码不存在"
    exit 1
fi

cd "$WIRESHARK_SRC"

# 应用补丁修复 getdtablesize() 问题（如果存在）
PATCH_FILE="wsutil/ws_pipe.c"
if [ -f "$PATCH_FILE" ]; then
    echo "检查是否需要修补 ws_pipe.c ..."
    if grep -q "getdtablesize" "$PATCH_FILE" 2>/dev/null; then
        echo "  应用补丁: getdtablesize() -> sysconf(_SC_OPEN_MAX)"
        sed -i 's/getdtablesize()/sysconf(_SC_OPEN_MAX)/g' "$PATCH_FILE"
    fi
fi

# 清理并重建
BUILD_DIR="build-android-16kb"
if [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# 构建 Host Lemon
LEMON_BIN="$INSTALL_DIR/bin/lemon"
mkdir -p "$INSTALL_DIR/bin"
if [ ! -f "$LEMON_BIN" ]; then
    echo "Building host lemon..."
    gcc -o "$LEMON_BIN" "$WIRESHARK_SRC/tools/lemon/lemon.c"
fi

# 配置 CMake（使用与之前成功配置相同的参数 + 16KB对齐）
cmake -G "Ninja" \
    -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="arm64-v8a" \
    -DANDROID_PLATFORM="android-$ANDROID_API" \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH="$INSTALL_DIR" \
    -DCMAKE_SHARED_LINKER_FLAGS="-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384" \
    -DCMAKE_EXE_LINKER_FLAGS="-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384" \
    -DBUILD_wireshark=OFF \
    -DBUILD_tshark=OFF \
    -DBUILD_sharkd=OFF \
    -DBUILD_dumpcap=OFF \
    -DBUILD_fuzzshark=OFF \
    -DBUILD_text2pcap=OFF \
    -DBUILD_mergecap=OFF \
    -DBUILD_reordercap=OFF \
    -DBUILD_capinfos=OFF \
    -DBUILD_captype=OFF \
    -DBUILD_rawshark=OFF \
    -DBUILD_dftest=OFF \
    -DBUILD_randpkt=OFF \
    -DBUILD_androiddump=OFF \
    -DBUILD_sshdump=OFF \
    -DBUILD_ciscodump=OFF \
    -DBUILD_dpauxmon=OFF \
    -DBUILD_sdjournal=OFF \
    -DENABLE_QT=OFF \
    -DENABLE_LUA=OFF \
    -DENABLE_SMI=OFF \
    -DENABLE_GNUTLS=OFF \
    -DENABLE_GCRYPT=OFF \
    -DENABLE_ZLIB=ON \
    -DENABLE_LZ4=OFF \
    -DENABLE_SNAPPY=OFF \
    -DENABLE_ZSTD=OFF \
    -DENABLE_BROTLI=OFF \
    -DENABLE_CAP=OFF \
    -DENABLE_PCAP=OFF \
    -DENABLE_AIRPCAP=OFF \
    -DENABLE_PLUGINS=OFF \
    -DENABLE_LIBXML2=OFF \
    -DENABLE_KERBEROS=OFF \
    -DENABLE_MINIZIP=OFF \
    -DENABLE_ILBC=OFF \
    -DENABLE_OPUS=OFF \
    -DENABLE_BCG729=OFF \
    -DENABLE_SPANDSP=OFF \
    -DENABLE_AMRNB=OFF \
    -DENABLE_NGHTTP2=OFF \
    -DENABLE_NGHTTP3=OFF \
    -DENABLE_SINSP=OFF \
    -DENABLE_CHECKHF_CONFLICT=OFF \
    -DHAVE_C99_VSNPRINTF=ON \
    -DHAVE_C99_VSNPRINTF_EXITCODE=0 \
    -DLEMON_EXECUTABLE="$LEMON_BIN" \
    -DGLIB2_FOUND=ON \
    -DGLIB2_LIBRARY="$INSTALL_DIR/lib/libglib-2.0.so" \
    -DGLIB2_MAIN_INCLUDE_DIR="$INSTALL_DIR/include/glib-2.0" \
    -DGLIB2_INTERNAL_INCLUDE_DIR="$INSTALL_DIR/lib/glib-2.0/include" \
    -DGMODULE2_LIBRARY="$INSTALL_DIR/lib/libgmodule-2.0.so" \
    -DGMODULE2_INCLUDE_DIR="$INSTALL_DIR/include/glib-2.0" \
    -DGTHREAD2_LIBRARY="$INSTALL_DIR/lib/libgthread-2.0.so" \
    -DGTHREAD2_INCLUDE_DIR="$INSTALL_DIR/include/glib-2.0" \
    -DGCRYPT_LIBRARY="$INSTALL_DIR/lib/libgcrypt.so" \
    -DGCRYPT_INCLUDE_DIR="$INSTALL_DIR/include" \
    -DGCRYPT_ERROR_LIBRARY="$INSTALL_DIR/lib/libgpg-error.so" \
    -DCARES_LIBRARY="$INSTALL_DIR/lib/libcares.so" \
    -DCARES_INCLUDE_DIR="$INSTALL_DIR/include" \
    -DPCRE2_LIBRARY="$INSTALL_DIR/lib/libpcre2-8.a" \
    -DPCRE2_INCLUDE_DIR="$INSTALL_DIR/include" \
    -DZLIB_LIBRARY="$INSTALL_DIR/lib/libz.a" \
    -DZLIB_INCLUDE_DIR="$INSTALL_DIR/include" \
    ..

# 编译
echo ""
echo "编译 wsutil、wiretap、libwireshark..."
ninja wsutil
ninja wiretap
ninja epan

# 安装
echo ""
echo "安装库..."
ninja install

# 手动复制（如果 install 未包含）
echo ""
echo "确保所有库已复制..."
mkdir -p "$INSTALL_DIR/lib"
cp run/libwsutil.so "$INSTALL_DIR/lib/" 2>/dev/null || true
cp run/libwiretap.so "$INSTALL_DIR/lib/" 2>/dev/null || true
cp run/libwireshark.so "$INSTALL_DIR/lib/" 2>/dev/null || true

echo ""
echo "[✓] Wireshark 4.0.10 重新编译完成（带 16KB 对齐）"

# 列出库
ls -lh "$INSTALL_DIR/lib/libws"*.so "$INSTALL_DIR/lib/libwiretap.so" 2>/dev/null
