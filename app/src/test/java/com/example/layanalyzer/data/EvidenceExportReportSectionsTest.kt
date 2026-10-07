// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.AgentSavedFinding
import com.example.layanalyzer.model.EvidenceExportMode
import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.EvidenceSource
import com.example.layanalyzer.model.WorkspaceNote
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * EVL-EXPORT-04: the `## 证据帧` Markdown table of `report.md`.
 *
 * The table construction was extracted into [EvidenceExportReportSections]
 * precisely so it can be asserted here: the ViewModel that renders the report
 * needs a `Context` and cannot run in a JVM test.
 */
class EvidenceExportReportSectionsTest {
    private val salt = "test-fingerprint"

    /** A note whose text is fully redactable: an IPv4 address and a host name. */
    private val redactableNote = "src=192.0.2.10 host=api.example.com"

    @Test
    fun `note is passed through unchanged in Original mode`() {
        val output = table(
            mode = EvidenceExportMode.Original,
            items = listOf(EvidenceItem(frameNumber = 41L)),
            notes = listOf(WorkspaceNote(frameNumber = 41L, text = redactableNote, updatedAtMillis = 1L))
        )

        assertTrue(output.contains(redactableNote))
    }

    @Test
    fun `note is redacted in Redacted mode`() {
        val output = table(
            mode = EvidenceExportMode.Redacted,
            items = listOf(EvidenceItem(frameNumber = 41L)),
            notes = listOf(WorkspaceNote(frameNumber = 41L, text = redactableNote, updatedAtMillis = 1L))
        )

        assertFalse(output.contains("192.0.2.10"))
        assertFalse(output.contains("api.example.com"))
        assertTrue(output.contains("host-"))
        assertTrue(output.contains("src=10."))
    }

    @Test
    fun `note text is absent in MetadataOnly mode`() {
        val output = table(
            mode = EvidenceExportMode.MetadataOnly,
            items = listOf(EvidenceItem(frameNumber = 41L)),
            notes = listOf(WorkspaceNote(frameNumber = 41L, text = redactableNote, updatedAtMillis = 1L))
        )

        assertFalse(output.contains("192.0.2.10"))
        assertFalse(output.contains("api.example.com"))
        assertTrue(output.contains(EvidenceExportReportSections.PLACEHOLDER))
    }

    @Test
    fun `a frame without a note gets the placeholder`() {
        val output = table(
            mode = EvidenceExportMode.Original,
            items = listOf(EvidenceItem(frameNumber = 41L))
        )

        assertEquals("| 41 | 手动 | — | — |", output.lineSequence().first { it.startsWith("| 41 ") })
    }

    @Test
    fun `manual evidence maps to the manual label`() {
        val output = table(
            mode = EvidenceExportMode.Original,
            items = listOf(EvidenceItem(frameNumber = 41L, source = EvidenceSource.Manual))
        )

        assertTrue(output.contains("| 41 | 手动 |"))
    }

    @Test
    fun `agent finding evidence maps to the finding label`() {
        val output = table(
            mode = EvidenceExportMode.Original,
            items = listOf(
                EvidenceItem(
                    frameNumber = 41L,
                    source = EvidenceSource.AgentFinding,
                    sourceFindingId = "finding-1"
                )
            )
        )

        assertTrue(output.contains("| 41 | 来自结论 |"))
    }

    @Test
    fun `the origin finding title is resolved by finding id`() {
        val output = table(
            mode = EvidenceExportMode.Original,
            items = listOf(
                EvidenceItem(
                    frameNumber = 41L,
                    source = EvidenceSource.AgentFinding,
                    sourceFindingId = "finding-1"
                )
            ),
            findings = listOf(finding("finding-1", "DNS 解析失败"))
        )

        assertTrue(output.contains("DNS 解析失败"))
    }

    @Test
    fun `a missing finding id yields the placeholder`() {
        val output = table(
            mode = EvidenceExportMode.Original,
            items = listOf(EvidenceItem(frameNumber = 41L, source = EvidenceSource.AgentFinding))
        )

        assertEquals("| 41 | 来自结论 | — | — |", output.lineSequence().first { it.startsWith("| 41 ") })
    }

    @Test
    fun `an unresolved finding id yields the placeholder instead of throwing`() {
        val output = table(
            mode = EvidenceExportMode.Original,
            items = listOf(
                EvidenceItem(
                    frameNumber = 41L,
                    source = EvidenceSource.AgentFinding,
                    sourceFindingId = "finding-gone"
                )
            ),
            findings = listOf(finding("finding-other", "无关结论"))
        )

        assertEquals("| 41 | 来自结论 | — | — |", output.lineSequence().first { it.startsWith("| 41 ") })
    }

    @Test
    fun `an empty evidence set states that there are no evidence frames and has no table`() {
        val output = table(mode = EvidenceExportMode.Original, items = emptyList())

        assertTrue(output.contains(EvidenceExportReportSections.NO_EVIDENCE_FRAMES))
        assertFalse(output.contains("帧号"))
        assertFalse(output.contains("|"))
    }

    @Test
    fun `pipes and line breaks in a note are flattened so the row keeps four columns`() {
        val output = table(
            mode = EvidenceExportMode.Original,
            items = listOf(EvidenceItem(frameNumber = 41L)),
            notes = listOf(
                WorkspaceNote(frameNumber = 41L, text = "line1|line2\nline3", updatedAtMillis = 1L)
            )
        )

        val row = output.lineSequence().first { it.startsWith("| 41 ") }
        assertTrue(row.contains("line1\\|line2 line3"))
        assertEquals(5, countUnescapedPipes(row))
    }

    @Test
    fun `pipes and line breaks in a finding title are flattened so the row keeps four columns`() {
        val output = table(
            mode = EvidenceExportMode.Original,
            items = listOf(
                EvidenceItem(
                    frameNumber = 41L,
                    source = EvidenceSource.AgentFinding,
                    sourceFindingId = "finding-1"
                )
            ),
            findings = listOf(finding("finding-1", "标题|带换行\n第二行"))
        )

        val row = output.lineSequence().first { it.startsWith("| 41 ") }
        assertTrue(row.contains("标题\\|带换行 第二行"))
        assertEquals(5, countUnescapedPipes(row))
    }

    @Test
    fun `header and separator have four columns`() {
        val output = table(
            mode = EvidenceExportMode.Original,
            items = listOf(EvidenceItem(frameNumber = 41L))
        )

        val lines = output.lines()
        assertEquals("| 帧号 | 来源 | 关联备注 | 来源结论标题 |", lines[0])
        assertEquals("| --- | --- | --- | --- |", lines[1])
    }

    @Test
    fun `rows are ascending by frame number regardless of input order`() {
        val ordered = listOf(
            EvidenceItem(frameNumber = 1L),
            EvidenceItem(frameNumber = 3L),
            EvidenceItem(frameNumber = 5L)
        )
        val shuffled = listOf(
            EvidenceItem(frameNumber = 5L),
            EvidenceItem(frameNumber = 1L),
            EvidenceItem(frameNumber = 3L)
        )

        val first = table(EvidenceExportMode.Original, ordered)
        val second = table(EvidenceExportMode.Original, shuffled)

        assertEquals(first, second)
        assertEquals("| 1 | 手动 | — | — |", first.lines()[2])
        assertEquals("| 3 | 手动 | — | — |", first.lines()[3])
        assertEquals("| 5 | 手动 | — | — |", first.lines()[4])
    }

    @Test
    fun `redaction without a redactor is refused rather than passed through`() {
        try {
            EvidenceExportReportSections.evidenceFramesTable(
                items = listOf(EvidenceItem(frameNumber = 41L)),
                notes = listOf(WorkspaceNote(frameNumber = 41L, text = redactableNote, updatedAtMillis = 1L)),
                findings = emptyList(),
                mode = EvidenceExportMode.Redacted,
                redactor = null
            )
            throw AssertionError("Expected redaction without a redactor to fail closed.")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message.orEmpty().contains("MetadataRedactor"))
        }
    }

    @Test
    fun `original mode never rewrites the note even without a redactor`() {
        val output = table(
            mode = EvidenceExportMode.Original,
            items = listOf(EvidenceItem(frameNumber = 41L)),
            notes = listOf(WorkspaceNote(frameNumber = 41L, text = redactableNote, updatedAtMillis = 1L))
        )

        assertNotEquals(redactableNote, MetadataRedactor(salt).redact(redactableNote))
        assertTrue(output.contains(redactableNote))
    }

    // ---- helpers -------------------------------------------------------------

    private fun table(
        mode: EvidenceExportMode,
        items: List<EvidenceItem>,
        notes: List<WorkspaceNote> = emptyList(),
        findings: List<AgentSavedFinding> = emptyList()
    ): String = EvidenceExportReportSections.evidenceFramesTable(
        items = items,
        notes = notes,
        findings = findings,
        mode = mode,
        redactor = if (mode == EvidenceExportMode.Original) null else MetadataRedactor(salt)
    )

    private fun finding(id: String, title: String): AgentSavedFinding = AgentSavedFinding(
        findingId = id,
        title = title,
        summary = "",
        sourceId = "source-1",
        savedAtMillis = 1L
    )

    /** A `|` is a column delimiter unless the preceding character escapes it. */
    private fun countUnescapedPipes(line: String): Int {
        var count = 0
        var escaped = false
        line.forEach { char ->
            when {
                escaped -> escaped = false
                char == '\\' -> escaped = true
                char == '|' -> count++
            }
        }
        return count
    }
}
