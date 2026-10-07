#!/bin/bash
# 辅助脚本：在设备上运行验证程序

echo "========================================"
echo "Running Wireshark Epan Verification"
echo "========================================"

# 设置库路径
export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH

# 赋予执行权限（如果还没有）
chmod +x hello_tshark 2>/dev/null

# 检查测试文件
if [ ! -f "test.pcap" ]; then
    echo "[ERROR] test.pcap not found in current directory"
    echo "Please push a test pcap file to /data/local/tmp/"
    exit 1
fi

# 运行验证
echo ""
./hello_tshark test.pcap

echo ""
echo "========================================"
