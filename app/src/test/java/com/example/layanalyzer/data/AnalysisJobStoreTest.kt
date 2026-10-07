package com.example.layanalyzer.data

import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentConversationRole
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AnalysisScope
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class AnalysisJobStoreTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    private fun store(now: Long = 1_000L): AnalysisJobStore =
        AnalysisJobStore(temporaryFolder.root, clock = { now })

    @Test
    fun `a checkpoint round-trips with all fields`() {
        val subject = store()
        val checkpoint = checkpoint(runId = "run_abc", conversationId = "conv_xyz")
        subject.write(checkpoint)

        val loaded = subject.list().single()
        assertEquals("run_abc", loaded.runId)
        assertEquals("conv_xyz", loaded.conversationId)
        assertEquals(AnalysisCheckpoint.Queued, loaded.checkpoint)
        assertEquals("fingerprint-a", loaded.captureFingerprint)
        assertEquals("Why is this slow?", loaded.question)
        assertFalse(loaded.interrupted)
    }

    @Test
    fun `markInterruptedOnStartup flips non-terminal checkpoints`() {
        val subject = store()
        subject.write(checkpoint(runId = "run_1"))
        subject.write(checkpoint(runId = "run_2", checkpoint = AnalysisCheckpoint.ModelRequestStarted))

        val marked = subject.markInterruptedOnStartup()

        assertEquals(2, marked)
        subject.list().forEach { job -> assertTrue(job.interrupted) }
    }

    @Test
    fun `markInterruptedOnStartup does not touch terminal checkpoints`() {
        val subject = store()
        subject.write(checkpoint(runId = "run_terminal", checkpoint = AnalysisCheckpoint.Terminal))

        val marked = subject.markInterruptedOnStartup()

        assertEquals(0, marked)
        assertFalse(subject.list().single().interrupted)
    }

    @Test
    fun `delete removes the job file`() {
        val subject = store()
        subject.write(checkpoint(runId = "run_del"))
        subject.delete("run_del")

        assertTrue(subject.list().isEmpty())
    }

    @Test
    fun `activeJob returns the non-terminal non-interrupted job`() {
        val subject = store()
        subject.write(checkpoint(runId = "run_live", checkpoint = AnalysisCheckpoint.Preparing))
        subject.write(checkpoint(runId = "run_done", checkpoint = AnalysisCheckpoint.Terminal))

        val active = subject.activeJob()

        assertNotNull(active)
        assertEquals("run_live", active!!.runId)
    }

    @Test
    fun `activeJob returns null when the only job is interrupted`() {
        val subject = store()
        subject.write(checkpoint(runId = "run_interrupted").copy(interrupted = true))

        assertNull(subject.activeJob())
    }

    @Test
    fun `a malformed file is skipped without hiding readable ones`() {
        val subject = store()
        subject.write(checkpoint(runId = "run_good"))
        File(temporaryFolder.root, "corrupt.json").writeText("not json")

        val listed = subject.list()

        assertEquals(1, listed.size)
        assertEquals("run_good", listed.single().runId)
    }

    @Test
    fun `the write is atomic — a temp file never stays behind`() {
        val subject = store()
        subject.write(checkpoint(runId = "run_atomic"))

        val tmpFiles = temporaryFolder.root.listFiles()
            ?.filter { it.name.endsWith(".tmp") }
            .orEmpty()
        assertTrue(tmpFiles.isEmpty())
    }

    @Test
    fun `clear removes all job files`() {
        val subject = store()
        subject.write(checkpoint(runId = "run_1"))
        subject.write(checkpoint(runId = "run_2"))
        val foreign = File(temporaryFolder.root, "not-mine.txt")
        foreign.writeText("keep")

        subject.clear()

        assertTrue(subject.list().isEmpty())
        assertTrue(foreign.isFile)
    }

    @Test
    fun `resumePolicy is ManualConfirm for ModelRequestStarted`() {
        val job = checkpoint(checkpoint = AnalysisCheckpoint.ModelRequestStarted)
        assertEquals(
            AnalysisResumePolicy.ManualConfirm,
            job.resumePolicy("fingerprint-a")
        )
    }

    @Test
    fun `resumePolicy is SafeToResume for ToolStarted`() {
        val job = checkpoint(checkpoint = AnalysisCheckpoint.ToolStarted)
        assertEquals(
            AnalysisResumePolicy.SafeToResume,
            job.resumePolicy("fingerprint-a")
        )
    }

    @Test
    fun `resumePolicy is CaptureUnavailable when fingerprints differ`() {
        val job = checkpoint(checkpoint = AnalysisCheckpoint.ToolStarted)
        assertEquals(
            AnalysisResumePolicy.CaptureUnavailable,
            job.resumePolicy("fingerprint-other")
        )
    }

    private fun checkpoint(
        runId: String = "run_test",
        conversationId: String = "conv_test",
        checkpoint: AnalysisCheckpoint = AnalysisCheckpoint.Queued
    ) = AnalysisJobCheckpoint(
        conversationId = conversationId,
        runId = runId,
        captureFingerprint = "fingerprint-a",
        captureLocalPath = "/data/captures/test.pcap",
        captureDisplayName = "test.pcap",
        scope = AnalysisScope.CompleteFile,
        privacyMode = AgentPrivacyMode.RedactedMetadata,
        question = "Why is this slow?",
        checkpoint = checkpoint,
        startedAtMillis = 1_000L
    )
}
