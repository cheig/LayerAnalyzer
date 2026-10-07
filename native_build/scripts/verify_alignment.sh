#!/bin/bash
set -e

echo "========================================="
echo "使用 llvm-objcopy 修复库对齐"
echo "========================================="

# 加载环境变量
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup.sh"

OUTPUT_LIB="$INSTALL_DIR/lib"
ANDROID_LIB="$PROJECT_ROOT/app/src/main/cpp/libs/arm64-v8a"

# 需要修复对齐的库列表
LIBS_TO_FIX=(
    "libgpg-error.so"
    "libgcrypt.so"
    "libcares.so"
    "libglib-2.0.so"
    "libgmodule-2.0.so"
    "libgobject-2.0.so"
    "libgthread-2.0.so"
    "libwsutil.so"
    "libwiretap.so"
    "libwireshark.so"
)

# 使用 NDK 的 llvm-objcopy 工具
OBJCOPY="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy"

if [ ! -f "$OBJCOPY" ]; then
    echo "错误: llvm-objcopy 未找到: $OBJCOPY"
    exit 1
fi

# 创建备份
BACKUP_DIR="$OUTPUT_LIB/backup_before_alignment_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "备份库到: $BACKUP_DIR"
for lib in "${LIBS_TO_FIX[@]}"; do
    if [ -f "$OUTPUT_LIB/$lib" ]; then
        cp "$OUTPUT_LIB/$lib" "$BACKUP_DIR/"
        echo "  ✓ 备份 $lib"
    fi
done

echo ""
echo "========================================="
echo "修改库段对齐为 16 KB"
echo "========================================="

# 修复每个库的对齐
for lib in "${LIBS_TO_FIX[@]}"; do
    LIB_PATH="$OUTPUT_LIB/$lib"
    
    if [ ! -f "$LIB_PATH" ]; then
        echo "⚠ 跳过 $lib (文件不存在)"
        continue
    fi
    
    echo "处理 $lib ..."
    
    # 方法1: 使用 patchelf (如果可用)
    if command -v patchelf &> /dev/null; then
        patchelf --page-size 16384 "$LIB_PATH" 2>/dev/null && echo "  ✓ 使用 patchelf 修改成功" && continue
    fi
    
    # 方法2: 使用 llvm-objcopy 设置段对齐
    # 注意: objcopy 不能直接修改 LOAD 段对齐，我们需要重新链接
    echo "  ⚠ llvm-objcopy 无法直接修改 LOAD 段对齐"
    echo "  → 此库需要重新编译"
done

echo ""
echo "========================================="
echo "验证对齐情况"
echo "========================================="

for lib in "${LIBS_TO_FIX[@]}"; do
    LIB_PATH="$OUTPUT_LIB/$lib"
    
    if [ ! -f "$LIB_PATH" ]; then
        continue
    fi
    
    echo ""
    echo ">>> $lib"
    readelf -l "$LIB_PATH" | grep -A 1 "LOAD" | grep "Align" || echo "  无法读取对齐信息"
done

echo ""
echo "========================================="
echo "注意: objcopy 无法修改 LOAD 段对齐"
echo "========================================="
echo "LOAD 段对齐在链接时确定，无法通过 objcopy 修改。"
echo "唯一可靠的方法是重新链接库时指定对齐参数。"
echo ""
echo "建议方案:"
echo "1. 使用已编译的库 (如果它们已经是 16KB 对齐)"
echo "2. 重新编译时添加正确的链接器标志"
echo ""
