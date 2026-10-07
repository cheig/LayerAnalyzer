#!/bin/bash
set -e

# ============================================================
# 任务3: GLib 及网络库编译 (x86_64)
# ============================================================

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup_x86_64.sh"

PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
EXTERNAL_DIR="$PROJECT_ROOT/native_build/external"
PATCH_DIR="$PROJECT_ROOT/native_build/patches/glib"

echo "===== 任务3: GLib 及网络库编译 (x86_64) ====="
echo "INSTALL_DIR: $INSTALL_DIR"
echo ""

# ============================================================
# 3.1 创建 dummy libintl.h
# ============================================================
echo "===== 步骤 3.1: 创建 dummy libintl.h ====="
mkdir -p "$INSTALL_DIR/include"
cat << 'EOF' > "$INSTALL_DIR/include/libintl.h"
#ifndef LIBINTL_H
#define LIBINTL_H
#ifdef __cplusplus
extern "C" {
#endif
#define gettext(String) (String)
#define dgettext(Domain,String) (String)
#define dcgettext(Domain,String,Type) (String)
#define ngettext(String1,String2,N) ((N) == 1 ? (String1) : (String2))
#define dngettext(Domain,String1,String2,N) ((N) == 1 ? (String1) : (String2))
#define dcngettext(Domain,String1,String2,N,Type) ((N) == 1 ? (String1) : (String2))
#define bindtextdomain(Domain,Directory) (Domain)
#define bind_textdomain_codeset(Domain,Codeset)
#define textdomain(String) (String)
#ifdef __cplusplus
}
#endif
#endif
EOF
echo "libintl.h 创建完成"

# ============================================================
# 3.2 编译 c-ares
# ============================================================
echo ""
echo "===== 步骤 3.2: 编译 c-ares ====="
cd "$EXTERNAL_DIR/c-ares-1.34.4"
rm -rf build-x86_64
mkdir build-x86_64
cd build-x86_64

cmake .. \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=x86_64 \
  -DANDROID_PLATFORM=android-$ANDROID_API \
  -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR \
  -DCARES_SHARED=ON \
  -DCARES_STATIC=OFF \
  -DCARES_BUILD_TESTS=OFF \
  -DCARES_BUILD_TOOLS=OFF \
  -DCMAKE_SHARED_LINKER_FLAGS="-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"

make -j$(nproc)
make install

echo "c-ares 编译完成"

# ============================================================
# 3.3 编译 glib
# ============================================================
echo ""
echo "===== 步骤 3.3: 编译 glib ====="
cd "$EXTERNAL_DIR/glib-2.80.0"

# 应用补丁 (如果尚未应用)
if [ ! -f ".patched" ]; then
    echo "应用 Termux 补丁..."
    for patch in "$PATCH_DIR"/*.patch; do
        if [ -f "$patch" ]; then
            echo "应用 $patch..."
            if ! patch -p1 --forward --batch < "$patch"; then
                echo "警告: 补丁 $patch 可能已应用或有冲突"
            fi
        fi
    done
    
    # 额外修复：GLib 2.80.0 强制 ENABLE_NLS=1
    sed -i "s/glib_conf.set('ENABLE_NLS', 1)/glib_conf.set('ENABLE_NLS', get_option('nls').allowed() ? 1 : 0)/" meson.build
    # 修复 glibintl.h 使用 #ifdef 而非 #if 的问题
    sed -i "s/ifdef ENABLE_NLS/if ENABLE_NLS/" glib/glibintl.h
    
    touch .patched
fi

# 清理旧构建
rm -rf _build_x86_64

# 配置 Meson
export PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig"
export PATH=$PATH:/usr/local/bin:~/.local/bin

CROSS_FILE="$PROJECT_ROOT/native_build/cross_file_x86_64.txt"
source "$SCRIPT_DIR/write_meson_cross_file.sh"

echo "使用 Meson 配置 GLib (交叉编译文件: $CROSS_FILE)..."
meson setup _build_x86_64 \
    --cross-file "$CROSS_FILE" \
    --prefix="$INSTALL_DIR" \
    --default-library=shared \
    -Dtests=false \
    -Dnls=disabled \
    -Dman=false \
    -Dgtk_doc=false \
    -Dbsymbolic_functions=false \
    -Dforce_posix_threads=true

echo "编译 GLib..."
meson compile -C _build_x86_64

echo "安装 GLib..."
meson install -C _build_x86_64

echo "GLib 编译完成"

# ============================================================
# 3.4 验证
# ============================================================
echo ""
echo "===== 步骤 3.4: 验证输出 ====="
echo "验证 c-ares:"
file "$INSTALL_DIR/lib/libcares.so" | grep x86-64 && echo "✓ libcares.so - x86_64" || echo "✗ libcares.so"

echo ""
echo "验证 glib:"
for lib in libglib-2.0.so libgmodule-2.0.so libgobject-2.0.so libgthread-2.0.so libgio-2.0.so; do
    if [ -f "$INSTALL_DIR/lib/$lib" ]; then
        file "$INSTALL_DIR/lib/$lib" | grep x86-64 && echo "✓ $lib - x86_64" || echo "✗ $lib"
    fi
done

echo ""
echo "===== 任务3 完成 ====="
echo "输出目录: $INSTALL_DIR/lib"
ls -la "$INSTALL_DIR/lib"/*.so 2>/dev/null || echo "(无动态库)"
