#!/bin/bash
# Source after env_setup_x86_64.sh with CROSS_FILE set.
cat > "$CROSS_FILE" <<EOF
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
cpu_family = '$ARCH'
cpu = '$ARCH'
endian = 'little'
EOF
