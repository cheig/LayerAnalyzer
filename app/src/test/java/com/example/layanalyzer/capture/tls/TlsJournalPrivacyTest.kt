// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture.tls

import com.example.layanalyzer.data.CaptureFileAccess
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CountDownLatch
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class TlsJournalPrivacyTest {
    @get:Rule val temporary = TemporaryFolder()
    private fun file() = File(temporary.root, "capture/tls-connections.jsonl")

    @Test fun utf8FileBudgetCountsLossWithoutFailingTheRelayOrChangingHistory() {
        val file = file()
        val record = "{\"sni\":\"例子.test\"}"
        val size = (record + "\n").toByteArray(Charsets.UTF_8).size.toLong()
        val journal = TlsConnectionJournal(file, maxFileBytes = size * 2)
        journal.use { sink -> repeat(6) { sink.offer(record) } }
        assertEquals(listOf(record, record), file.readLines())
        assertEquals(size * 2, file.length())
        assertEquals(2L, journal.queueMetrics.persisted)
        assertEquals(4L, journal.queueMetrics.capacityDropped)
        assertEquals(4L, journal.droppedLines)
        assertEquals(0L, journal.queueMetrics.writeFailures)
        assertEquals(file.length(), journal.queueMetrics.fileBytes)
        assertFalse(journal.queueMetrics.workerAlive)
    }

    @Test fun reopenKeepsOldRecordsAndEnforcesTheRemainingByteBudget() {
        val file = file()
        TlsConnectionJournal(file, maxFileBytes = 6).use { it.offer("one") }
        val reopened = TlsConnectionJournal(file, maxFileBytes = 6)
        reopened.use { it.offer("two") }
        assertEquals("one\n", file.readText())
        assertEquals(listOf("one"), reopened.readLines(10))
        assertEquals(1L, reopened.queueMetrics.capacityDropped)
        assertEquals(0L, reopened.queueMetrics.writeFailures)
    }

    @Test fun multilineAndOversizedRecordsCannotForgeExtraHistoryEntries() {
        val file = file()
        val journal = TlsConnectionJournal(file)
        journal.use {
            it.offer("one\ntwo")
            it.offer("one\rtwo")
            it.offer("x".repeat(8193))
            it.offer("valid")
        }
        assertEquals(listOf("valid"), file.readLines())
        assertEquals(3L, journal.droppedLines)
        assertEquals(1L, journal.queueMetrics.persisted)
    }

    @Test fun oversizedLegacyLineAndIncompleteTailAreNotReloadedAsEvents() {
        val file = file().apply { parentFile!!.mkdirs(); writeText("x".repeat(8193) + "\n") }
        TlsConnectionJournal(file).use { assertTrue(it.readLines(Int.MAX_VALUE).isEmpty()) }
        file.writeText("complete\npartial")
        TlsConnectionJournal(file).use { assertEquals(listOf("complete"), it.readLines(Int.MAX_VALUE)) }
    }

    @Test fun closeTimeoutRetainsOwnershipUntilTheActualWriterExit() {
        val file = file()
        val gate = CountDownLatch(1)
        lateinit var worker: Thread
        val journal = TlsConnectionJournal(file, 4, 1024, { runnable ->
            Thread({ gate.await(); runnable.run() }).also { worker = it }
        })
        try {
            journal.offer("accepted-before-stop")
            journal.close()
            assertTrue(journal.queueMetrics.closeTimedOut)
            expectInUse { CaptureFileAccess.idle(listOf(file.parentFile!!)) { fail("writer lost ownership") } }
            journal.offer("after-stop")
            assertEquals(1L, journal.droppedLines)
        } finally {
            gate.countDown()
            worker.join(5000)
            journal.close()
        }
        assertFalse(worker.isAlive)
        assertEquals(listOf("accepted-before-stop"), file.readLines())
        CaptureFileAccess.idle(listOf(file.parentFile!!)) { assertTrue(file.delete()) }
    }

    @Test fun writerCreatesPrivateMetadataAndKeepsSiblingCaptureUntouched() {
        val file = file()
        val sibling = temporary.newFile("sibling.jsonl").apply { writeText("keep") }
        TlsConnectionJournal(file).use { it.offer("ordinary metadata") }
        assertEquals("keep", sibling.readText())
        if (file.toPath().fileSystem.supportedFileAttributeViews().contains("posix")) {
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(file.toPath()))
            assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(file.parentFile!!.toPath()))
        }
    }

    @Test fun invalidFileBudgetsFailBeforeAllocatingAWriterOrDirectory() {
        for (size in listOf(0L, -1L, 16L * 1024 * 1024 + 1)) {
            try { TlsConnectionJournal(file(), maxFileBytes = size); fail("invalid budget") }
            catch (_: IllegalArgumentException) { }
        }
        assertFalse(file().parentFile!!.exists())
    }

    @Test fun explicitPrivateRootRejectsOutsideTargetsBeforeStartingWriter() {
        val root = temporary.newFolder("private-root")
        val outside = File(temporary.root, "outside/events.jsonl")
        try {
            TlsConnectionJournal(outside, privateRoot = root)
            fail("outside target accepted")
        } catch (_: IllegalArgumentException) { }
        assertFalse(outside.parentFile!!.exists())
        val inside = File(root, "capture/events.jsonl")
        TlsConnectionJournal(inside, privateRoot = root).use { it.offer("ordinary metadata") }
        assertEquals(listOf("ordinary metadata"), inside.readLines())
    }

    private fun expectInUse(block: () -> Unit) {
        try { block(); fail("expected IN_USE") }
        catch (error: TlsAssetException) { assertEquals(TlsAssetErrorCode.IN_USE, error.code) }
    }
}
