#!/bin/bash
# =====================================================
# 16 KB 页面对齐修复脚本
# 用于解决 Android 15+ (API 35+) 的兼容性问题
# =====================================================
set -e

# 加载环境变量
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup.sh"

# ================= 配置区域 =================
echo "========================================="
echo "16 KB Alignment Fix Script"
echo "========================================="

# 添加 16 KB 对齐链接器标志
export LDFLAGS="$LDFLAGS -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"
export CFLAGS="$CFLAGS"
export CXXFLAGS="$CXXFLAGS"

echo "Updated LDFLAGS: $LDFLAGS"
echo ""

# 要重新编译的库列表（按依赖顺序）
LIBS_TO_REBUILD=(
    "libgpg-error"
    "libgcrypt"
    "c-ares"
    "glib"
    "wireshark_core"
)

# 确认用户意图
echo "将重新编译以下库以支持 16 KB 对齐："
for lib in "${LIBS_TO_REBUILD[@]}"; do
    echo "  - $lib"
done
echo ""
echo "预计耗时：30-60 分钟"
echo "按 Enter 开始编译，Ctrl+C 取消..."
read -r

# 创建备份目录
BACKUP_DIR="$INSTALL_DIR/backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "备份现有库到 $BACKUP_DIR ..."
if [ -d "$INSTALL_DIR/lib" ]; then
    cp -r "$INSTALL_DIR/lib"/*.so* "$BACKUP_DIR/" 2>/dev/null || true
fi

# ================= 1. libgpg-error =================
echo ""
echo "========================================="
echo "[1/5] 重新编译 libgpg-error with 16KB alignment"
echo "========================================="

cd "$PROJECT_ROOT/native_build/external"
GPG_ERROR_VER="1.50"
cd "libgpg-error-$GPG_ERROR_VER"

# 清理旧编译
make clean || true
rm -f Makefile config.status config.log

# 重新配置
./configure --host=$TARGET_HOST --prefix=$INSTALL_DIR \
    --disable-doc --disable-tests --disable-nls --disable-languages

# 编译安装
make -j$(nproc)
make install

echo "[✓] libgpg-error 完成"

# ================= 2. libgcrypt =================
echo ""
echo "========================================="
echo "[2/5] 重新编译 libgcrypt with 16KB alignment"
echo "========================================="

cd "$PROJECT_ROOT/native_build/external"
GCRYPT_VER="1.11.0"
cd "libgcrypt-$GCRYPT_VER"

# 清理旧编译
make clean || true
rm -f Makefile config.status config.log

# 重新配置
./configure --host=$TARGET_HOST --prefix=$INSTALL_DIR \
    --with-libgpg-error-prefix=$INSTALL_DIR \
    --disable-doc --disable-tests \
    --disable-asm

# 编译安装
make -j$(nproc)
make install

echo "[✓] libgcrypt 完成"

# ================= 3. c-ares =================
echo ""
echo "========================================="
echo "[3/5] 重新编译 c-ares with 16KB alignment"
echo "========================================="

cd "$PROJECT_ROOT/native_build/external"
CARES_VER="1.34.4"
cd "c-ares-$CARES_VER"

# 清理旧构建
if [ -d "build-android" ]; then
    rm -rf "build-android"
fi

mkdir -p build-android
cd build-android

# 使用 CMake 构建（添加 16KB 对齐标志）
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

echo "[✓] c-ares 完成"

# ================= 4. GLib =================
echo ""
echo "========================================="
echo "[4/5] 重新编译 GLib with 16KB alignment"
echo "========================================="

cd "$PROJECT_ROOT/native_build/external"
GLIB_VERSION="2.80.0"
cd "glib-$GLIB_VERSION"

# 清理旧构建
if [ -d "_build" ]; then
    rm -rf "_build"
fi

# 重新生成 Meson Cross File（带16KB对齐标志）
CROSS_FILE="$PROJECT_ROOT/native_build/cross_file_aarch64.txt"
cat <<EOF > "$CROSS_FILE"
[binaries]
c = '$CC'
cpp = '$CXX'
ar = '$AR'
strip = '$STRIP'
pkg-config = 'pkg-config'

[built-in options]
c_args = ['-I$INSTALL_DIR/include']
cpp_args = ['-I$INSTALL_DIR/include']
c_link_args = ['-L$INSTALL_DIR/lib', '-Wl,-z,max-page-size=16384', '-Wl,-z,common-page-size=16384']
cpp_link_args = ['-L$INSTALL_DIR/lib', '-Wl,-z,max-page-size=16384', '-Wl,-z,common-page-size=16384']

[properties]
sys_root = '$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/sysroot'
needs_exe_wrapper = true
glib_have_typeof = true

[host_machine]
system = 'android'
cpu_family = 'aarch64'
cpu = 'aarch64'
endian = 'little'
EOF

# 配置构建
export PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig"
export PATH=$PATH:/usr/local/bin:~/.local/bin

meson setup _build \
    --cross-file "$CROSS_FILE" \
    --prefix="$INSTALL_DIR" \
    --default-library=shared \
    -Dtests=false \
    -Dnls=disabled \
    -Dman=false \
    -Dgtk_doc=false \
    -Dbsymbolic_functions=false \
    -Dforce_posix_threads=true

# 编译和安装
meson compile -C _build
meson install -C _build

echo "[✓] GLib 完成"

# ================= 5. Wireshark Core =================
echo ""
echo "========================================="
echo "[5/5] 重新编译 Wireshark (wsutil, wiretap, libwireshark) with 16KB alignment"
echo "========================================="

cd "$PROJECT_ROOT/native_build/external"
WIRESHARK_VER="4.4.2"
cd "wireshark-$WIRESHARK_VER"

# 清理旧构建
if [ -d "build" ]; then
    rm -rf "build"
fi

mkdir -p build
cd build

# 配置 CMake（添加16KB对齐标志）
cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-$ANDROID_API \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR \
    -DCMAKE_PREFIX_PATH=$INSTALL_DIR \
    -DCMAKE_SHARED_LINKER_FLAGS="-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384" \
    -DCMAKE_EXE_LINKER_FLAGS="-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384" \
    -DENABLE_STATIC=OFF \
    -DBUILD_wireshark=OFF \
    -DBUILD_tshark=OFF \
    -DBUILD_dumpcap=OFF \
    -DBUILD_editcap=OFF \
    -DBUILD_capinfos=OFF \
    -DBUILD_mergecap=OFF \
    -DBUILD_text2pcap=OFF \
    -DBUILD_reordercap=OFF \
    -DBUILD_randpkt=OFF \
    -DBUILD_dftest=OFF \
    -DBUILD_rawshark=OFF \
    -DBUILD_sharkd=OFF \
    -DENABLE_PLUGINS=OFF \
    -DENABLE_LUA=OFF \
    -DCARES_INCLUDE_DIR=$INSTALL_DIR/include \
    -DCARES_LIBRARY=$INSTALL_DIR/lib/libcares.so \
    -DGLIB2_INCLUDE_DIRS="$INSTALL_DIR/include/glib-2.0;$INSTALL_DIR/lib/glib-2.0/include" \
    -DGLIB2_LIBRARIES="$INSTALL_DIR/lib/libglib-2.0.so;$INSTALL_DIR/lib/libgobject-2.0.so;$INSTALL_DIR/lib/libgmodule-2.0.so"

# 编译
make -j$(nproc)

# 手动安装关键库
mkdir -p $INSTALL_DIR/lib
cp run/libwsutil.so $INSTALL_DIR/lib/
cp run/libwiretap.so $INSTALL_DIR/lib/
cp run/libwireshark.so $INSTALL_DIR/lib/

echo "[✓] Wireshark Core 完成"

# ================= 验证结果 =================
echo ""
echo "========================================="
echo "16 KB 对齐验证"
echo "========================================="

VERIFY_LIBS=(
    "$INSTALL_DIR/lib/libgpg-error.so"
    "$INSTALL_DIR/lib/libgcrypt.so"
    "$INSTALL_DIR/lib/libcares.so"
    "$INSTALL_DIR/lib/libglib-2.0.so"
    "$INSTALL_DIR/lib/libgmodule-2.0.so"
    "$INSTALL_DIR/lib/libgobject-2.0.so"
    "$INSTALL_DIR/lib/libgthread-2.0.so"
    "$INSTALL_DIR/lib/libwsutil.so"
    "$INSTALL_DIR/lib/libwiretap.so"
    "$INSTALL_DIR/lib/libwireshark.so"
)

# 安装 readelf（如果未安装）
if ! command -v readelf &> /dev/null; then
    echo "Installing binutils for readelf..."
    sudo apt-get update && sudo apt-get install -y binutils
fi

echo "检查 LOAD 段对齐情况..."
for lib in "${VERIFY_LIBS[@]}"; do
    if [ -f "$lib" ]; then
        echo ""
        echo ">>> $(basename $lib)"
        readelf -l "$lib" | grep -A 2 "LOAD" | grep -E "LOAD|Align" || echo "  [警告] 未找到对齐信息"
    else
        echo "  [错误] 文件不存在: $lib"
    fi
done

# ================= 复制到 Android 项目 =================
echo ""
echo "========================================="
echo "复制编译结果到 Android 项目"
echo "========================================="

TARGET_DIR="$PROJECT_ROOT/app/src/main/cpp/libs/arm64-v8a"
mkdir -p "$TARGET_DIR"

echo "复制 .so 文件到 $TARGET_DIR ..."
for lib in "${VERIFY_LIBS[@]}"; do
    if [ -f "$lib" ]; then
        cp -v "$lib" "$TARGET_DIR/"
    fi
done

echo ""
echo "========================================="
echo "✓ 16 KB 对齐修复完成！"
echo "========================================="
echo "备份位置: $BACKUP_DIR"
echo "新库位置: $INSTALL_DIR/lib"
echo "Android 项目库: $TARGET_DIR"
echo ""
echo "下一步操作："
echo "1. 在 Android Studio 中执行 Gradle Sync"
echo "2. 清理构建: ./gradlew clean"
echo "3. 重新构建: ./gradlew assembleDebug"
echo "4. 安装测试: adb install -r app/build/outputs/apk/debug/app-debug.apk"
echo "========================================="
