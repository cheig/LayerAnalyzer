#!/bin/bash
set -e

# Source environment setup
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup.sh"

WIRESHARK_VER="4.0.10"
WIRESHARK_TAR="wireshark-$WIRESHARK_VER.tar.xz"
WIRESHARK_URL="https://2.na.dl.wireshark.org/src/$WIRESHARK_TAR"
EXT_DIR="$PROJECT_ROOT/native_build/external"
SRC_DIR="$EXT_DIR/wireshark-$WIRESHARK_VER"
BUILD_DIR="$SRC_DIR/build-android"

# ================= 1. Get Source =================
if [ ! -d "$SRC_DIR" ]; then
    echo "[INFO] Cloning Wireshark $WIRESHARK_VER..."
    mkdir -p "$EXT_DIR"
    cd "$EXT_DIR"
    # Clone specific tag with depth 1 for speed
    git clone --depth 1 --branch "v$WIRESHARK_VER" https://gitlab.com/wireshark/wireshark.git "wireshark-$WIRESHARK_VER"
fi

# ================= 1.5 Build Host Lemon (for Cross-Compile) =================
echo "[INFO] Building Host Lemon..."
LEMON_BIN="$INSTALL_DIR/bin/lemon"
mkdir -p "$INSTALL_DIR/bin"
if [ ! -f "$LEMON_BIN" ]; then
    gcc -o "$LEMON_BIN" "$SRC_DIR/tools/lemon/lemon.c"
fi

# ================= 2. Configure =================
echo "[INFO] Configuring CMake..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Note: We explicitly point to our GLib build to avoid confusion
cmake -G "Ninja" \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI="arm64-v8a" \
  -DANDROID_PLATFORM="android-$ANDROID_API" \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$INSTALL_DIR" \
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
  -DLEMON_EXECUTABLE="$INSTALL_DIR/bin/lemon" \
  \
  -DGLIB2_FOUND=ON \
  -DGLIB2_LIBRARY="$INSTALL_DIR/lib/libglib-2.0.so" \
  -DGLIB2_MAIN_INCLUDE_DIR="$INSTALL_DIR/include/glib-2.0" \
  -DGLIB2_INTERNAL_INCLUDE_DIR="$INSTALL_DIR/lib/glib-2.0/include" \
  \
  -DGMODULE2_LIBRARY="$INSTALL_DIR/lib/libgmodule-2.0.so" \
  -DGMODULE2_INCLUDE_DIR="$INSTALL_DIR/include/glib-2.0" \
  \
  -DGTHREAD2_LIBRARY="$INSTALL_DIR/lib/libgthread-2.0.so" \
  -DGTHREAD2_INCLUDE_DIR="$INSTALL_DIR/include/glib-2.0" \
  \
  -DGCRYPT_LIBRARY="$INSTALL_DIR/lib/libgcrypt.so" \
  -DGCRYPT_INCLUDE_DIR="$INSTALL_DIR/include" \
  -DGCRYPT_ERROR_LIBRARY="$INSTALL_DIR/lib/libgpg-error.so" \
  \
  -DCARES_LIBRARY="$INSTALL_DIR/lib/libcares.so" \
  -DCARES_INCLUDE_DIR="$INSTALL_DIR/include" \
  \
  -DPCRE2_LIBRARY="$INSTALL_DIR/lib/libpcre2-8.a" \
  -DPCRE2_INCLUDE_DIR="$INSTALL_DIR/include" \
  \
  -DZLIB_LIBRARY="$INSTALL_DIR/lib/libz.a" \
  -DZLIB_INCLUDE_DIR="$INSTALL_DIR/include" \
  \
  ..

# ================= 3. Build =================
echo "[INFO] Building wsutil..."
ninja wsutil

echo "[INFO] Building wiretap..."
ninja wiretap

# ================= 4. Install =================
echo "[INFO] Installing libs and headers..."
# We use 'cmake --install' or just 'ninja install'. 
# Since we disabled everything else, this should only install what we built + headers.
ninja install

# ================= 5. Verify =================
echo "[INFO] Verifying installation..."
if [ -f "$INSTALL_DIR/lib/libwiretap.so" ] && [ -f "$INSTALL_DIR/lib/libwsutil.so" ]; then
    echo "SUCCESS: Libraries installed."
    ls -lh "$INSTALL_DIR/lib/libwiretap.so"
    ls -lh "$INSTALL_DIR/lib/libwsutil.so"
    file "$INSTALL_DIR/lib/libwiretap.so"
else
    echo "ERROR: Compilation or installation failed."
    exit 1
fi
