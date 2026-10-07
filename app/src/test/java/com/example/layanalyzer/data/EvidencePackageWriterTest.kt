package com.example.layanalyzer.data

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipFile

class EvidencePackageWriterTest {
    @Test
    fun `metadata package has required files and no capture`() {
        val output = File.createTempFile("evidence", ".zip")
        try {
            EvidencePackageWriter().write(output, "{\"schemaVersion\":1}", "# report", "[]")
            ZipFile(output).use { zip ->
                assertTrue(zip.getEntry("report.json") != null)
                assertTrue(zip.getEntry("report.md") != null)
                assertTrue(zip.getEntry("frames.json") != null)
                assertFalse(zip.entries().asSequence().any { it.name.startsWith("capture/") })
            }
        } finally {
            output.delete()
        }
    }

    @Test
    fun `original package preserves capture bytes`() {
        val output = File.createTempFile("evidence", ".zip")
        val capture = File.createTempFile("capture", ".pcap").apply { writeBytes(byteArrayOf(1, 2, 3, 4)) }
        try {
            EvidencePackageWriter().write(output, "{}", "", "[]", capture)
            ZipFile(output).use { zip ->
                val entry = zip.getEntry("capture/${capture.name}")
                assertArrayEquals(capture.readBytes(), zip.getInputStream(entry).readBytes())
                assertEquals(4L, entry.size)
            }
        } finally {
            capture.delete()
            output.delete()
        }
    }

    @Test
    fun `package writes named Agent report additions without replacing core entries`() {
        val output = File.createTempFile("evidence", ".zip")
        try {
            EvidencePackageWriter().write(
                output = output,
                manifestJson = "{}",
                reportMarkdown = "",
                framesJson = "[]",
                additionalEntries = mapOf(
                    "agent-report.json" to "{\"schemaVersion\":1}",
                    "agent-report.md" to "# Agent",
                    "agent-run.json" to "{}"
                )
            )
            ZipFile(output).use { zip ->
                assertTrue(zip.getEntry("report.json") != null)
                assertTrue(zip.getEntry("agent-report.json") != null)
                assertTrue(zip.getEntry("agent-report.md") != null)
                assertTrue(zip.getEntry("agent-run.json") != null)
            }
        } finally {
            output.delete()
        }
    }
}
