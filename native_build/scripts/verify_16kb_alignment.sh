#!/bin/bash

# ==============================================================================
# 验证 native_build/output/lib 中的 .so 库是否满足 16KB 页面对齐
# ==============================================================================

# 加载环境变量以获取 INSTALL_DIR
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ -f "$SCRIPT_DIR/env_setup.sh" ]; then
    source "$SCRIPT_DIR/env_setup.sh"
else
    echo "警告: 未找到 env_setup.sh，使用默认路径"
    PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
    INSTALL_DIR="$PROJECT_ROOT/native_build/output"
fi

LIB_DIR="$INSTALL_DIR/lib"

if [ ! -d "$LIB_DIR" ]; then
    echo "错误: 目录不存在: $LIB_DIR"
    exit 1
fi

echo "====================================================="
echo "正在检查 16KB 对齐情况: $LIB_DIR"
echo "====================================================="

SUCCESS_COUNT=0
FAILURE_COUNT=0
TOTAL_COUNT=0

# 检查 readelf 是否可用
if ! command -v readelf &> /dev/null; then
    echo "错误: 系统中未找到 readelf 工具"
    exit 1
fi

# 获取所有 .so 文件
SO_FILES=$(find "$LIB_DIR" -maxdepth 1 -name "*.so")

for lib in $SO_FILES; do
    LIB_NAME=$(basename "$lib")
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    
    # 获取所有 LOAD 段的对齐值
    # readelf -lW 输出示例如下：
    # LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x0113f4 0x0113f4 R E 0x4000
    # 我们取出最后一列 (Align)
    
    ALIGNMENTS=$(readelf -lW "$lib" | grep "LOAD" | awk '{print $NF}' | sort -u)
    
    IS_ALIGNED=true
    MIN_ALIGN=0
    
    for align in $ALIGNMENTS; do
        # 将十六进制转换为十进制进行比较 (例如 0x4000 -> 16384)
        DEC_ALIGN=$(printf "%d" "$align")
        if [ "$MIN_ALIGN" -eq 0 ] || [ "$DEC_ALIGN" -lt "$MIN_ALIGN" ]; then
            MIN_ALIGN=$DEC_ALIGN
        fi
        
        if [ "$DEC_ALIGN" -lt 16384 ]; then
            IS_ALIGNED=false
        fi
    done
    
    if [ "$IS_ALIGNED" = true ]; then
        echo -e "[\e[32mPASS\e[0m] $LIB_NAME (最小对齐: $((MIN_ALIGN / 1024))KB)"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo -e "[\e[31mFAIL\e[0m] $LIB_NAME (最小对齐: $((MIN_ALIGN / 1024))KB)"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    fi
done

echo "====================================================="
echo "检查完成:"
echo "  总计: $TOTAL_COUNT"
echo "  通过: $SUCCESS_COUNT"
echo "  失败: $FAILURE_COUNT"
echo "====================================================="

if [ $FAILURE_COUNT -gt 0 ]; then
    exit 1
fi
exit 0
