package com.example.layanalyzer.model

/** "显示分组字节"弹窗的显示格式（对齐 Wireshark Show data as 下拉） */
enum class PacketBytesFormat {
    RAW,      // 原始数据：小写十六进制连续串，每 32 字节换行
    ASCII,    // ASCII：可打印字符，其余 '.'；CR/LF 输出为换行
    JSON,     // JSON：解析后 2 空格缩进美化；失败抛 BytesFormatException
    HEX_DUMP, // Hex 转储：Wireshark 风格 偏移 + hex + ASCII 三栏
    UTF8      // UTF-8 解码（非法序列替换为 U+FFFD）
}
