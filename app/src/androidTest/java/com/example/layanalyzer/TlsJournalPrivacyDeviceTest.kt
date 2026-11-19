// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Context
import android.system.Os
import androidx.core.content.FileProvider
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.capture.tls.TlsConnectionJournal
import java.io.File
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Disposable synthetic metadata only; never opens a VPN or modifies user CA/captures. */
@RunWith(AndroidJUnit4::class)
class TlsJournalPrivacyDeviceTest {
    @Test fun privateJournalPermissionsAndShareExclusionSurviveReopen() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val directory = File(context.filesDir, "captures/r07-journal-${UUID.randomUUID()}")
        val file = File(directory, "tls-connections.jsonl")
        try {
            val journal = TlsConnectionJournal(file, privateRoot = context.filesDir)
            journal.use { it.offer("{\"captureId\":\"synthetic\"}") }
            assertEquals("Journal must write in Android's ordinary private storage", 0L, journal.queueMetrics.writeFailures)
            assertEquals(1L, journal.queueMetrics.persisted)
            assertEquals(448, Os.stat(directory.path).st_mode and 511)
            assertEquals(384, Os.stat(file.path).st_mode and 511)
            TlsConnectionJournal(file, privateRoot = context.filesDir).use { assertEquals(1, it.readLines(10).size) }
            for (privateFile in listOf(file, File(context.noBackupFilesDir, "tls-analysis-leases/keys.log"),
                File(context.noBackupFilesDir, "tls-ca/private-key.enc"))) {
                try {
                    FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", privateFile)
                    fail("Private storage received a share URI")
                } catch (_: IllegalArgumentException) { }
            }
        } finally {
            // Exact UUID namespace created by this test; no recursive user-data cleanup.
            if (file.exists()) assertTrue(file.delete())
            if (directory.exists()) assertTrue(directory.delete())
        }
    }

    @Test fun byteLimitAndRealFilesystemFailureKeepSeparateLossCounters() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val root = File(context.filesDir, "r07-journal-${UUID.randomUUID()}").apply { check(mkdir()) }
        try {
            val file = File(root, "bounded/events.jsonl")
            val record = "{\"host\":\"例子.test\"}"
            val size = (record + "\n").toByteArray(Charsets.UTF_8).size.toLong()
            val bounded = TlsConnectionJournal(file, maxFileBytes = size, privateRoot = context.filesDir)
            bounded.use { it.offer(record); it.offer(record) }
            assertEquals(size, file.length())
            assertEquals(1L, bounded.queueMetrics.persisted)
            assertEquals(1L, bounded.queueMetrics.capacityDropped)
            assertEquals(0L, bounded.queueMetrics.writeFailures)
            assertEquals(listOf(record), bounded.readLines())
            val blocked = File(root, "blocked").apply { writeText("synthetic obstruction") }
            val failed = TlsConnectionJournal(File(blocked, "events.jsonl"), privateRoot = context.filesDir)
            failed.use { it.offer(record) }
            assertEquals(1L, failed.queueMetrics.writeFailures)
            assertEquals(1L, failed.queueMetrics.notPersisted)
            assertEquals(0L, failed.queueMetrics.capacityDropped)
            assertEquals("synthetic obstruction", blocked.readText())
            assertEquals(listOf(record), bounded.readLines())
        } finally {
            check(root.canonicalFile.parentFile == context.filesDir.canonicalFile)
            assertTrue(root.deleteRecursively())
        }
    }

    @Test fun redirectedParentCannotWriteIntoASiblingCapture() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val root = File(context.filesDir, "r07-links-${UUID.randomUUID()}").apply { check(mkdir()) }
        try {
            val sibling = File(root, "sibling").apply { check(mkdir()) }
            val keep = File(sibling, "keep").apply { writeText("keep") }
            val redirect = File(root, "redirect")
            Os.symlink(sibling.path, redirect.path)
            val journal = TlsConnectionJournal(File(redirect, "events.jsonl"), privateRoot = context.filesDir)
            journal.use { it.offer("ordinary metadata") }
            assertEquals(1L, journal.queueMetrics.writeFailures)
            assertEquals("keep", keep.readText())
            assertFalse(File(sibling, "events.jsonl").exists())
            assertTrue(redirect.delete())
        } finally {
            File(root, "redirect").delete()
            assertTrue(root.deleteRecursively())
        }
    }
}
