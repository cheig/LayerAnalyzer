// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CaptureFileValidatorTest {
    @Test
    fun acceptsPcapByteOrdersAndPcapng() {
        assertTrue(CaptureFileValidator.isSupportedMagic(bytes(0xd4, 0xc3, 0xb2, 0xa1)))
        assertTrue(CaptureFileValidator.isSupportedMagic(bytes(0xa1, 0xb2, 0xc3, 0xd4)))
        assertTrue(CaptureFileValidator.isSupportedMagic(bytes(0x4d, 0x3c, 0xb2, 0xa1)))
        assertTrue(CaptureFileValidator.isSupportedMagic(bytes(0xa1, 0xb2, 0x3c, 0x4d)))
        assertTrue(CaptureFileValidator.isSupportedMagic(bytes(0x0a, 0x0d, 0x0d, 0x0a)))
    }

    @Test
    fun rejectsShortOrUnrelatedFiles() {
        assertFalse(CaptureFileValidator.isSupportedMagic(byteArrayOf(0x0a)))
        assertFalse(CaptureFileValidator.isSupportedMagic("PK!!".toByteArray()))
        assertFalse(CaptureFileValidator.isSupportedMagic("text".toByteArray()))
    }

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }
}
