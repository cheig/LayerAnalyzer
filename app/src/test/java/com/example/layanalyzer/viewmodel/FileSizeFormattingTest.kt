package com.example.layanalyzer.viewmodel

import org.junit.Assert.assertEquals
import org.junit.Test

class FileSizeFormattingTest {
    @Test
    fun formatsBoundaryValues() {
        assertEquals("Unknown size", (-1L).formatFileSize())
        assertEquals("0 B", 0L.formatFileSize())
        assertEquals("1023 B", 1023L.formatFileSize())
        assertEquals("1.0 KB", 1024L.formatFileSize())
        assertEquals("1.0 MB", (1024L * 1024L).formatFileSize())
        assertEquals("1.5 GB", (1536L * 1024L * 1024L).formatFileSize())
        assertEquals("8388608.0 TB", Long.MAX_VALUE.formatFileSize())
    }
}
