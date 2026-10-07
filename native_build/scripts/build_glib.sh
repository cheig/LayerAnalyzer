#!/bin/bash
set -e

# 加载环境变量
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup.sh"
export PATH=$PATH:/usr/local/bin:~/.local/bin

GLIB_VERSION="2.80.0"
GLIB_TAR="glib-${GLIB_VERSION}.tar.xz"
GLIB_URL="https://download.gnome.org/sources/glib/2.80/${GLIB_TAR}"
EXTERNAL_DIR="$PROJECT_ROOT/native_build/external"
PATCH_DIR="$PROJECT_ROOT/native_build/patches/glib"

# 0. 准备依赖环境 (Dummy libintl.h)
# Android NDK 缺失 libintl.h，且 GLib 2.80 强制需要 ENABLE_NLS
mkdir -p "$INSTALL_DIR/include"
cat << EOF > "$INSTALL_DIR/include/libintl.h"
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

# 1. 下载和解压
cd "$EXTERNAL_DIR"
if [ ! -d "glib-${GLIB_VERSION}" ] && [ ! -f "$GLIB_TAR" ]; then
    echo "Downloading GLib $GLIB_VERSION..."
    wget "$GLIB_URL"
fi

if [ ! -d "glib-${GLIB_VERSION}" ]; then
    echo "Extracting GLib $GLIB_VERSION..."
    tar -xf "$GLIB_TAR"
fi

cd "glib-${GLIB_VERSION}"

# 2. 应用补丁 (如果尚未应用)
if [ ! -f ".patched" ]; then
    echo "Applying patches from Termux..."
    for patch in "$PATCH_DIR"/*.patch; do
        if [ -f "$patch" ]; then
            echo "Applying $patch..."
            if ! patch -p1 --forward --batch < "$patch"; then
                echo "Warning: patch $patch failed to apply smoothly, please check manually if needed."
            fi
        fi
    done
    
    # 额外修复：GLib 2.80.0 强制 ENABLE_NLS=1，需要修改以支持禁用
    sed -i "s/glib_conf.set('ENABLE_NLS', 1)/glib_conf.set('ENABLE_NLS', get_option('nls').allowed() ? 1 : 0)/" meson.build
    # 修复 glibintl.h 使用 #ifdef 而非 #if 的问题
    sed -i "s/ifdef ENABLE_NLS/if ENABLE_NLS/" glib/glibintl.h
    
    touch .patched
fi

# 3. 生成 Meson Cross File
CROSS_FILE="$PROJECT_ROOT/native_build/cross_file_aarch64.txt"
echo "Generating Meson cross file at $CROSS_FILE..."

cat << EOF > "$CROSS_FILE"
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

# 4. 配置构建
if [ -d "_build" ]; then
    rm -rf "_build"
fi

echo "Configuring GLib with Meson..."
export PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig"

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

# 5. 编译和安装
echo "Compiling GLib..."
meson compile -C _build

echo "Installing GLib..."
meson install -C _build

echo "GLib build completed successfully!"
