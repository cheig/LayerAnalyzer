#!/bin/bash
set -e

# ================= 环境配置 =================
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/../scripts/env_setup.sh"

VERIFICATION_DIR="$PROJECT_ROOT/native_build/verification"
cd "$VERIFICATION_DIR"

echo "========================================"
echo "Building hello_tshark Verification Program"
echo "========================================"

# ================= 编译参数 =================
# 头文件路径
INCLUDE_FLAGS="-I$INSTALL_DIR/include \
  -I$INSTALL_DIR/include/glib-2.0 \
  -I$INSTALL_DIR/lib/glib-2.0/include \
  -I$INSTALL_DIR/include/wireshark \
  -I$INSTALL_DIR/include/wireshark/epan \
  -I$INSTALL_DIR/include/wireshark/wiretap \
  -I$INSTALL_DIR/include/wireshark/wsutil"

# 库链接顺序（从依赖少到依赖多）
LINK_FLAGS="-L$INSTALL_DIR/lib \
  -lwireshark \
  -lwiretap \
  -lwsutil \
  -lglib-2.0 \
  -lgmodule-2.0 \
  -lgobject-2.0 \
  -lgcrypt \
  -lgpg-error \
  -lcares \
  -lz \
  -lm \
  -ldl"

# 编译选项
COMPILE_FLAGS="-target aarch64-linux-android${ANDROID_API} \
  -fPIC \
  -D__ANDROID_API__=$ANDROID_API"

# ================= 执行编译 =================
echo "[INFO] Compiling hello_tshark.c..."
$CC $COMPILE_FLAGS $INCLUDE_FLAGS -o hello_tshark hello_tshark.c $LINK_FLAGS

# ================= 验证产物 =================
if [ -f "hello_tshark" ]; then
    echo "[SUCCESS] hello_tshark compiled successfully"
    echo ""
    echo "Binary Information:"
    file hello_tshark
    echo ""
    echo "Size:"
    ls -lh hello_tshark
    echo ""
    echo "========================================"
    echo "Next Steps:"
    echo "1. Prepare test.pcap file"
    echo "2. Push to Android device:"
    echo "   adb push hello_tshark /data/local/tmp/"
    echo "   adb push test.pcap /data/local/tmp/"
    echo "   cd $INSTALL_DIR/lib && adb push *.so /data/local/tmp/"
    echo "3. Run on device:"
    echo "   adb shell"
    echo "   cd /data/local/tmp"
    echo "   chmod +x hello_tshark"
    echo "   export LD_LIBRARY_PATH=.:\$LD_LIBRARY_PATH"
    echo "   ./hello_tshark test.pcap"
    echo "========================================"
else
    echo "[ERROR] Compilation failed"
    exit 1
fi
