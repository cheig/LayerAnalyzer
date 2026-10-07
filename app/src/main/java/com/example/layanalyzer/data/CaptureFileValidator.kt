package com.example.layanalyzer.data

object CaptureFileValidator {
    fun isSupportedMagic(header: ByteArray): Boolean {
        if (header.size < 4) return false
        val first = header[0].toInt() and 0xff
        val second = header[1].toInt() and 0xff
        val third = header[2].toInt() and 0xff
        val fourth = header[3].toInt() and 0xff
        return (first == 0xd4 && second == 0xc3 && third == 0xb2 && fourth == 0xa1) ||
            (first == 0xa1 && second == 0xb2 && third == 0xc3 && fourth == 0xd4) ||
            (first == 0x4d && second == 0x3c && third == 0xb2 && fourth == 0xa1) ||
            (first == 0xa1 && second == 0xb2 && third == 0x3c && fourth == 0x4d) ||
            (first == 0x0a && second == 0x0d && third == 0x0d && fourth == 0x0a)
    }
}
