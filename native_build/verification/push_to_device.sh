#!/bin/bash
# 辅助脚本：在 WSL2 中推送所有文件到 Android 设备

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
INSTALL_DIR="$PROJECT_ROOT/native_build/output"
VERIFICATION_DIR="$PROJECT_ROOT/native_build/verification"

echo "========================================"
echo "Pushing Verification Files to Android"
echo "========================================"

# ================= 1. 推送可执行文件 =================
if [ ! -f "$VERIFICATION_DIR/hello_tshark" ]; then
    echo "[ERROR] hello_tshark not found. Please build it first:"
    echo "  cd $VERIFICATION_DIR"
    echo "  ./build_hello_tshark.sh"
    exit 1
fi

echo "[1/3] Pushing hello_tshark..."
adb push "$VERIFICATION_DIR/hello_tshark" /data/local/tmp/
echo ""

# ================= 2. 推送测试数据 =================
if [ -f "$VERIFICATION_DIR/test.pcap" ]; then
    echo "[2/3] Pushing test.pcap..."
    adb push "$VERIFICATION_DIR/test.pcap" /data/local/tmp/
    echo ""
else
    echo "[WARNING] test.pcap not found. You need to provide a test pcap file."
    echo "  Place it at: $VERIFICATION_DIR/test.pcap"
    echo ""
fi

# ================= 3. 推送依赖库 =================
echo "[3/3] Pushing dependency libraries..."
cd "$INSTALL_DIR/lib"

# 核心库
adb push libwireshark.so /data/local/tmp/
adb push libwiretap.so /data/local/tmp/
adb push libwsutil.so /data/local/tmp/

# GLib 系列
adb push libglib-2.0.so /data/local/tmp/
adb push libgmodule-2.0.so /data/local/tmp/
adb push libgobject-2.0.so /data/local/tmp/

# 其他依赖
adb push libgcrypt.so /data/local/tmp/
adb push libgpg-error.so /data/local/tmp/
adb push libcares.so /data/local/tmp/

echo ""
echo "========================================"
echo "Push Complete!"
echo "========================================"
echo ""
echo "To run on device:"
echo "  adb shell"
echo "  cd /data/local/tmp"
echo "  chmod +x hello_tshark"
echo "  export LD_LIBRARY_PATH=.:\$LD_LIBRARY_PATH"
echo "  ./hello_tshark test.pcap"
echo ""
