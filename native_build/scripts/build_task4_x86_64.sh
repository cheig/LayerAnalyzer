#!/bin/bash
set -e

# ============================================================
# 任务4: Wireshark 核心库编译 (x86_64)
# ============================================================

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup_x86_64.sh"

PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
EXTERNAL_DIR="$PROJECT_ROOT/native_build/external"

WIRESHARK_VER="4.0.10"
SRC_DIR="$EXTERNAL_DIR/wireshark-$WIRESHARK_VER"
BUILD_DIR="$SRC_DIR/build-android-x86_64"

echo "===== 任务4: Wireshark 核心库编译 (x86_64) ====="
echo "INSTALL_DIR: $INSTALL_DIR"
echo ""

# ============================================================
# 4.1 编译 Host Lemon
# ============================================================
echo "===== 步骤 4.1: 编译 Host Lemon ====="
LEMON_BIN="$INSTALL_DIR/bin/lemon"
mkdir -p "$INSTALL_DIR/bin"
if [ ! -f "$LEMON_BIN" ]; then
    echo "编译 lemon..."
    gcc -o "$LEMON_BIN" "$SRC_DIR/tools/lemon/lemon.c"
    echo "lemon 编译完成: $LEMON_BIN"
else
    echo "lemon 已存在: $LEMON_BIN"
fi

# ============================================================
# 4.2 配置 Wireshark CMake
# ============================================================
echo ""
echo "===== 步骤 4.2: 配置 Wireshark CMake ====="
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake -G "Ninja" \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=x86_64 \
  -DANDROID_PLATFORM=android-$ANDROID_API \
  -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_PREFIX_PATH=$INSTALL_DIR \
  -DCMAKE_SHARED_LINKER_FLAGS="-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384" \
  -DCMAKE_EXE_LINKER_FLAGS="-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384" \
  \
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
  \
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
  -DLEMON_EXECUTABLE=$INSTALL_DIR/bin/lemon \
  \
  -DGLIB2_FOUND=ON \
  -DGLIB2_LIBRARY=$INSTALL_DIR/lib/libglib-2.0.so \
  -DGLIB2_MAIN_INCLUDE_DIR=$INSTALL_DIR/include/glib-2.0 \
  -DGLIB2_INTERNAL_INCLUDE_DIR=$INSTALL_DIR/lib/glib-2.0/include \
  -DGMODULE2_LIBRARY=$INSTALL_DIR/lib/libgmodule-2.0.so \
  -DGMODULE2_INCLUDE_DIR=$INSTALL_DIR/include/glib-2.0 \
  -DGTHREAD2_LIBRARY=$INSTALL_DIR/lib/libgthread-2.0.so \
  -DGTHREAD2_INCLUDE_DIR=$INSTALL_DIR/include/glib-2.0 \
  -DGCRYPT_LIBRARY=$INSTALL_DIR/lib/libgcrypt.so \
  -DGCRYPT_INCLUDE_DIR=$INSTALL_DIR/include \
  -DGCRYPT_ERROR_LIBRARY=$INSTALL_DIR/lib/libgpg-error.so \
  -DCARES_LIBRARY=$INSTALL_DIR/lib/libcares.so \
  -DCARES_INCLUDE_DIR=$INSTALL_DIR/include \
  -DPCRE2_LIBRARY=$INSTALL_DIR/lib/libpcre2-8.a \
  -DPCRE2_INCLUDE_DIR=$INSTALL_DIR/include \
  -DZLIB_LIBRARY=$INSTALL_DIR/lib/libz.a \
  -DZLIB_INCLUDE_DIR=$INSTALL_DIR/include \
  ..

# ============================================================
# 4.3 编译和安装
# ============================================================
echo ""
echo "===== 步骤 4.3: 编译 Wireshark 库 ====="
echo "编译 wsutil..."
ninja wsutil

echo "编译 wiretap..."
ninja wiretap

echo "编译 epan..."
ninja epan

echo ""
echo "===== 步骤 4.4: 安装库文件 ====="
ninja install

# ============================================================
# 4.5 验证
# ============================================================
echo ""
echo "===== 步骤 4.5: 验证输出 ====="

echo "验证 Wireshark 库:"
for lib in libwsutil.so libwiretap.so libwireshark.so; do
    if [ -f "$INSTALL_DIR/lib/$lib" ]; then
        file "$INSTALL_DIR/lib/$lib" | grep x86-64 && echo "✓ $lib - x86_64" || echo "✗ $lib 架构不正确"
    else
        echo "✗ $lib 不存在"
    fi
done

# 验证 16KB 对齐
echo ""
echo "验证 16KB 页面对齐:"
for lib in libwsutil.so libwiretap.so libwireshark.so; do
    if [ -f "$INSTALL_DIR/lib/$lib" ]; then
        ALIGN=$(readelf -l "$INSTALL_DIR/lib/$lib" 2>/dev/null | grep -A1 "LOAD" | grep -oP "0x[0-9a-f]+" | tail -1)
        if [ ! -z "$ALIGN" ]; then
            ALIGN_DEC=$((ALIGN))
            if [ $ALIGN_DEC -ge 16384 ]; then
                echo "✓ $lib - 对齐: $ALIGN ($ALIGN_DEC bytes)"
            else
                echo "⚠ $lib - 对齐: $ALIGN ($ALIGN_DEC bytes) - 可能不满足 16KB"
            fi
        fi
    fi
done

echo ""
echo "===== 任务4 完成 ====="
echo "输出目录: $INSTALL_DIR/lib"
ls -la "$INSTALL_DIR/lib"/*.so 2>/dev/null | head -20
