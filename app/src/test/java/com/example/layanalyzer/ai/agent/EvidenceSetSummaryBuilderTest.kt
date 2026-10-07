package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AnalysisWorkspace
import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.EvidenceSource
import com.example.layanalyzer.model.WorkspaceNote
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EvidenceSetSummaryBuilderTest {

    private val identityRedactor: (String) -> String = { it }

    private fun workspace(
        evidenceItems: List<EvidenceItem>,
        notes: List<WorkspaceNote> = emptyList()
    ): AnalysisWorkspace = AnalysisWorkspace(
        fileFingerprint = "fp",
        displayName = "capture.pcap",
        notes = notes,
        evidenceItems = evidenceItems
    )

    private fun note(frameNumber: Long, text: String, updatedAtMillis: Long = 1L) =
        WorkspaceNote(
            frameNumber = frameNumber,
            text = text,
            updatedAtMillis = updatedAtMillis
        )

    @Test
    fun `empty evidence set returns null`() {
        assertNull(EvidenceSetSummaryBuilder.build(workspace(emptyList()), identityRedactor))
    }

    @Test
    fun `small set lists frames provenance and note summary`() {
        val subject = workspace(
            evidenceItems = listOf(
                EvidenceItem(frameNumber = 12, source = EvidenceSource.Manual, addedAtMillis = 1L),
                EvidenceItem(
                    frameNumber = 15,
                    source = EvidenceSource.AgentFinding,
                    sourceFindingId = "finding_abc",
                    addedAtMillis = 2L
                )
            ),
            notes = listOf(note(12, "retransmission after 200 OK"))
        )

        val summary = EvidenceSetSummaryBuilder.build(subject, identityRedactor)!!

        assertTrue(summary.contains("Frames: 12, 15"))
        assertTrue(summary.contains("- frame 12: source=Manual"))
        assertTrue(summary.contains("- frame 15: source=AgentFinding (findingId=finding_abc)"))
        assertTrue(summary.contains("retransmission after 200 OK"))
        assertTrue(summary.contains("note: none"))
        // Each item stays on its own line.
        assertTrue(summary.lineSequence().any { it == "- frame 12: source=Manual; note: retransmission after 200 OK" })
        assertTrue(summary.lineSequence().any { it == "- frame 15: source=AgentFinding (findingId=finding_abc); note: none" })
    }

    @Test
    fun `note is joined by frame number and unmatched notes stay out`() {
        val subject = workspace(
            evidenceItems = listOf(
                EvidenceItem(frameNumber = 7, source = EvidenceSource.Manual)
            ),
            notes = listOf(
                note(9, "note for another frame"),
                note(7, "matched note text")
            )
        )

        val summary = EvidenceSetSummaryBuilder.build(subject, identityRedactor)!!

        assertTrue(summary.contains("matched note text"))
        assertFalse(summary.contains("note for another frame"))
    }

    @Test
    fun `agent finding item shows its sourceFindingId`() {
        val subject = workspace(
            evidenceItems = listOf(
                EvidenceItem(
                    frameNumber = 100,
                    source = EvidenceSource.AgentFinding,
                    sourceFindingId = "finding_xyz"
                )
            )
        )

        val summary = EvidenceSetSummaryBuilder.build(subject, identityRedactor)!!

        assertTrue(summary.contains("source=AgentFinding (findingId=finding_xyz)"))
    }

    @Test
    fun `more than forty frames lists forty and declares the rest`() {
        val subject = workspace(
            evidenceItems = (1L..45L).map { EvidenceItem(frameNumber = it, source = EvidenceSource.Manual) }
        )

        val summary = EvidenceSetSummaryBuilder.build(subject, identityRedactor)!!

        assertTrue(summary.contains("Evidence set summary (45 frame(s))"))
        assertTrue(summary.contains("and 5 more frames not listed"))
        assertTrue(summary.contains(", 40 and 5 more frames not listed"))
        assertFalse(summary.contains(", 41"))
        assertFalse(summary.contains(", 45"))
    }

    @Test
    fun `exactly forty frames lists all without a more declaration`() {
        val subject = workspace(
            evidenceItems = (1L..40L).map { EvidenceItem(frameNumber = it, source = EvidenceSource.Manual) }
        )

        val summary = EvidenceSetSummaryBuilder.build(subject, identityRedactor)!!

        assertTrue(summary.contains("40"))
        assertFalse(summary.contains("more frames not listed"))
    }

    @Test
    fun `long note is cut with an explicit note level marker`() {
        val longText = "x".repeat(300)
        val subject = workspace(
            evidenceItems = listOf(EvidenceItem(frameNumber = 3, source = EvidenceSource.Manual)),
            notes = listOf(note(3, longText))
        )

        val summary = EvidenceSetSummaryBuilder.build(subject, identityRedactor)!!

        val notePart = summary.lineSequence().first { it.startsWith("- frame 3") }
        val noteSummary = notePart.substringAfter("note: ")
        assertTrue(noteSummary.length <= EvidenceSetSummaryBuilder.MAX_NOTE_SUMMARY_CHARS)
        assertTrue(noteSummary.endsWith("[note truncated]"))
    }

    @Test
    fun `note text is passed through the redactor before capping`() {
        val subject = workspace(
            evidenceItems = listOf(EvidenceItem(frameNumber = 3, source = EvidenceSource.Manual)),
            notes = listOf(note(3, "call from 10.0.0.5 dropped"))
        )
        val redactor: (String) -> String = { it.replace("10.0.0.5", "ip4-1.invalid") }

        val summary = EvidenceSetSummaryBuilder.build(subject, redactor)!!

        assertTrue(summary.contains("ip4-1.invalid"))
        assertFalse(summary.contains("10.0.0.5"))
    }

    @Test
    fun `section longer than the cap is cut with the explicit truncated declaration`() {
        val longNoteText = "y".repeat(200)
        val subject = workspace(
            evidenceItems = (1L..60L).map { EvidenceItem(frameNumber = it, source = EvidenceSource.Manual) },
            notes = (1L..60L).map { note(it, longNoteText) }
        )

        val summary = EvidenceSetSummaryBuilder.build(subject, identityRedactor)!!

        assertTrue(summary.length <= EvidenceSetSummaryBuilder.MAX_SECTION_CHARS)
        assertTrue(summary.contains("[truncated:"))
        assertTrue(summary.contains("items shown]"))
        // The cut never happens silently: the declared shown count matches the lines present.
        val shownCount = summary.lineSequence().count { it.startsWith("- frame ") }
        val declaredCount = summary
            .substringAfterLast("; ")
            .substringBefore(" items shown")
            .substringBefore(" of")
            .trim()
            .toInt()
        assertEquals(shownCount, declaredCount)
    }

    @Test
    fun `summary within the cap carries no truncated declaration`() {
        val subject = workspace(
            evidenceItems = (1L..30L).map { EvidenceItem(frameNumber = it, source = EvidenceSource.Manual) },
            notes = (1L..30L).map { note(it, "short note $it") }
        )

        val summary = EvidenceSetSummaryBuilder.build(subject, identityRedactor)!!

        assertTrue(summary.length <= EvidenceSetSummaryBuilder.MAX_SECTION_CHARS)
        assertFalse(summary.contains("[truncated:"))
        assertFalse(summary.contains("items shown]"))
        assertEquals(30, summary.lineSequence().count { it.startsWith("- frame ") })
    }

    @Test
    fun `latest note wins when a frame carries several notes`() {
        val subject = workspace(
            evidenceItems = listOf(EvidenceItem(frameNumber = 5, source = EvidenceSource.Manual)),
            notes = listOf(
                note(5, "older note", updatedAtMillis = 1L),
                note(5, "newer note", updatedAtMillis = 2L)
            )
        )

        val summary = EvidenceSetSummaryBuilder.build(subject, identityRedactor)!!

        assertTrue(summary.contains("newer note"))
        assertFalse(summary.contains("older note"))
    }
}
