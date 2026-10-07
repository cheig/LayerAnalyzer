// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import com.example.layanalyzer.data.EvidenceFrameFilter
import com.example.layanalyzer.data.EvidenceFrameViewDecision
import com.example.layanalyzer.data.EvidenceFrameViewPolicy
import com.example.layanalyzer.data.EvidenceFrameViewRejection
import com.example.layanalyzer.model.AgentSavedFinding
import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.EvidenceSource
import com.example.layanalyzer.model.WorkspaceNote
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EvidenceWorkbenchModelTest {

    private fun manual(frame: Long, addedAtMillis: Long = 0L) = EvidenceItem(
        frameNumber = frame,
        source = EvidenceSource.Manual,
        sourceFindingId = null,
        addedAtMillis = addedAtMillis
    )

    private fun agent(frame: Long, findingId: String? = null, addedAtMillis: Long = 0L) = EvidenceItem(
        frameNumber = frame,
        source = EvidenceSource.AgentFinding,
        sourceFindingId = findingId,
        addedAtMillis = addedAtMillis
    )

    private fun note(frame: Long, text: String, updatedAtMillis: Long) = WorkspaceNote(
        frameNumber = frame,
        text = text,
        updatedAtMillis = updatedAtMillis
    )

    private fun finding(sourceId: String, title: String) = AgentSavedFinding(
        findingId = "fid-$sourceId",
        title = title,
        summary = "",
        sourceId = sourceId,
        sourceToolCallIds = emptyList(),
        evidenceFrames = emptySet(),
        savedAtMillis = 0L
    )

    @Test
    fun `empty items produce an empty row list`() {
        val rows = EvidenceWorkbench.rows(emptyList(), emptyList(), emptyList(), 0, EvidenceGroup.All)

        assertTrue(rows.isEmpty())
    }

    @Test
    fun `Manual-only workspace yields Manual rows without a finding title`() {
        val rows = EvidenceWorkbench.rows(listOf(manual(2L)), emptyList(), emptyList(), 10, EvidenceGroup.All)

        assertEquals(1, rows.size)
        assertEquals(EvidenceSource.Manual, rows[0].source)
        assertNull(rows[0].sourceFindingTitle)
    }

    @Test
    fun `AgentFinding-only workspace yields AgentFinding rows with the resolved title`() {
        val rows = EvidenceWorkbench.rows(
            listOf(agent(4L, "f1")),
            emptyList(),
            listOf(finding("f1", "Resolved title")),
            10,
            EvidenceGroup.All
        )

        assertEquals(1, rows.size)
        assertEquals(EvidenceSource.AgentFinding, rows[0].source)
        assertEquals("Resolved title", rows[0].sourceFindingTitle)
    }

    @Test
    fun `group All keeps both manual and agent findings`() {
        val items = listOf(manual(1L), agent(2L, "f1"))
        val rows = EvidenceWorkbench.rows(items, emptyList(), listOf(finding("f1", "T")), 10, EvidenceGroup.All)

        assertEquals(2, rows.size)
    }

    @Test
    fun `group Manual drops agent findings`() {
        val items = listOf(manual(1L), agent(2L, "f1"))
        val rows = EvidenceWorkbench.rows(items, emptyList(), listOf(finding("f1", "T")), 10, EvidenceGroup.Manual)

        assertEquals(1, rows.size)
        assertEquals(EvidenceSource.Manual, rows[0].source)
    }

    @Test
    fun `group FromFindings keeps only agent findings`() {
        val items = listOf(manual(1L), agent(2L, "f1"))
        val rows = EvidenceWorkbench.rows(items, emptyList(), listOf(finding("f1", "T")), 10, EvidenceGroup.FromFindings)

        assertEquals(1, rows.size)
        assertEquals(EvidenceSource.AgentFinding, rows[0].source)
    }

    @Test
    fun `sourceFindingId resolving to a finding shows its title`() {
        val rows = EvidenceWorkbench.rows(
            listOf(agent(5L, "f1")),
            emptyList(),
            listOf(finding("f1", "Found title")),
            10,
            EvidenceGroup.All
        )

        assertEquals("Found title", rows[0].sourceFindingTitle)
    }

    @Test
    fun `unresolved sourceFindingId keeps the row with a null title`() {
        val rows = EvidenceWorkbench.rows(
            listOf(agent(5L, "missing")),
            emptyList(),
            listOf(finding("f1", "Found title")),
            10,
            EvidenceGroup.All
        )

        assertEquals(1, rows.size)
        assertNull(rows[0].sourceFindingTitle)
    }

    @Test
    fun `null sourceFindingId keeps the row with a null title`() {
        val rows = EvidenceWorkbench.rows(
            listOf(agent(5L, null)),
            emptyList(),
            listOf(finding("f1", "Found title")),
            10,
            EvidenceGroup.All
        )

        assertEquals(1, rows.size)
        assertNull(rows[0].sourceFindingTitle)
    }

    @Test
    fun `note text is linked by frame number`() {
        val rows = EvidenceWorkbench.rows(
            listOf(manual(7L)),
            listOf(note(7L, "hello", 1L)),
            emptyList(),
            10,
            EvidenceGroup.All
        )

        assertEquals("hello", rows[0].noteText)
    }

    @Test
    fun `missing note leaves noteText null`() {
        val rows = EvidenceWorkbench.rows(
            listOf(manual(7L)),
            listOf(note(8L, "other", 1L)),
            emptyList(),
            10,
            EvidenceGroup.All
        )

        assertNull(rows[0].noteText)
    }

    @Test
    fun `multiple notes on the same frame keep the most recently updated`() {
        val notes = listOf(
            note(7L, "old", 100L),
            note(7L, "new", 300L),
            note(7L, "mid", 200L)
        )
        val rows = EvidenceWorkbench.rows(listOf(manual(7L)), notes, emptyList(), 10, EvidenceGroup.All)

        assertEquals("new", rows[0].noteText)
    }

    @Test
    fun `rows are emitted in ascending frame order regardless of input order`() {
        val items = listOf(manual(9L), manual(2L), manual(5L), manual(1L))
        val rows = EvidenceWorkbench.rows(items, emptyList(), emptyList(), 10, EvidenceGroup.All)

        assertEquals(listOf(1L, 2L, 5L, 9L), rows.map { it.frameNumber })
    }

    @Test
    fun `duplicate frame numbers are de-duplicated without dropping other frames`() {
        val items = listOf(
            agent(3L, "f_new", addedAtMillis = 50L),
            agent(3L, "f_old", addedAtMillis = 10L),
            manual(1L)
        )
        val rows = EvidenceWorkbench.rows(
            items,
            emptyList(),
            listOf(finding("f_new", "New"), finding("f_old", "Old")),
            10,
            EvidenceGroup.All
        )

        assertEquals(listOf(1L, 3L), rows.map { it.frameNumber })
        assertEquals("Old", rows.first { it.frameNumber == 3L }.sourceFindingTitle)
    }

    @Test
    fun `frameCount of zero never marks a frame stale`() {
        val items = listOf(manual(0L), manual(5L), manual(999L))
        val rows = EvidenceWorkbench.rows(items, emptyList(), emptyList(), 0, EvidenceGroup.All)

        assertTrue(rows.none { it.isStale })
    }

    @Test
    fun `frame beyond frameCount is stale`() {
        val rows = EvidenceWorkbench.rows(listOf(manual(11L)), emptyList(), emptyList(), 10, EvidenceGroup.All)

        assertTrue(rows[0].isStale)
    }

    @Test
    fun `frame below one is stale`() {
        val rows = EvidenceWorkbench.rows(listOf(manual(0L)), emptyList(), emptyList(), 10, EvidenceGroup.All)

        assertTrue(rows[0].isStale)
    }

    @Test
    fun `staleCount counts only stale rows`() {
        val items = listOf(manual(1L), manual(0L), manual(11L), manual(5L))
        val rows = EvidenceWorkbench.rows(items, emptyList(), emptyList(), 10, EvidenceGroup.All)

        assertEquals(2, EvidenceWorkbench.staleCount(rows))
    }

    @Test
    fun `visibleFrames is empty for an empty row list`() {
        val frames = EvidenceWorkbench.visibleFrames(emptyList())

        assertTrue(frames.isEmpty())
    }

    @Test
    fun `visibleFrames follows the row order`() {
        val rows = EvidenceWorkbench.rows(
            listOf(manual(9L), manual(2L), manual(5L), manual(1L)),
            emptyList(),
            emptyList(),
            10,
            EvidenceGroup.All
        )

        assertEquals(listOf(1L, 2L, 5L, 9L), EvidenceWorkbench.visibleFrames(rows))
    }

    @Test
    fun `visibleFrames de-duplicates while keeping row order`() {
        val rows = listOf(
            EvidenceRow(3L, EvidenceSource.AgentFinding, "Old", null, false),
            EvidenceRow(1L, EvidenceSource.Manual, null, null, false),
            EvidenceRow(3L, EvidenceSource.AgentFinding, "New", null, false),
            EvidenceRow(5L, EvidenceSource.Manual, null, null, false)
        )

        assertEquals(listOf(3L, 1L, 5L), EvidenceWorkbench.visibleFrames(rows))
    }

    // EVL-UI-05: "analyze with this evidence" entry gating.

    private fun assertAnalyzeInvariants(state: EvidenceAnalyzeActionState) {
        // enabled iff no blocking reason.
        assertEquals(state.enabled, state.reason == null)
        if (state.enabled) {
            // an enabled entry always carries a verbatim, non-blank filter.
            assertTrue(state.filter != null && state.filter.isNotBlank())
        } else {
            // a disabled entry never yields a submittable filter.
            assertTrue(state.reason != null)
        }
    }

    @Test
    fun `analyzeAction enables for a compiled Apply decision when idle`() {
        val decision = EvidenceFrameViewDecision.Apply(filter = "frame.number==5", frameCount = 1)
        val state = EvidenceWorkbench.analyzeAction(decision, isAgentRunning = false)

        assertTrue(state.enabled)
        assertNull(state.reason)
        assertEquals("frame.number==5", state.filter)
        assertEquals(1, state.frameCount)
        assertAnalyzeInvariants(state)
    }

    @Test
    fun `analyzeAction blocks with AgentRunning even for a compiled Apply decision`() {
        val decision = EvidenceFrameViewDecision.Apply(filter = "frame.number==5", frameCount = 1)
        val state = EvidenceWorkbench.analyzeAction(decision, isAgentRunning = true)

        assertFalse(state.enabled)
        assertEquals(EvidenceAnalyzeBlockReason.AgentRunning, state.reason)
        // The Apply values are still carried, but the entry is not submittable.
        assertEquals("frame.number==5", state.filter)
        assertEquals(1, state.frameCount)
        assertAnalyzeInvariants(state)
    }

    @Test
    fun `analyzeAction blocks an empty evidence set`() {
        val decision = EvidenceFrameViewDecision.Reject(EvidenceFrameViewRejection.EmptySet)
        val state = EvidenceWorkbench.analyzeAction(decision, isAgentRunning = false)

        assertFalse(state.enabled)
        assertEquals(EvidenceAnalyzeBlockReason.EmptySet, state.reason)
        assertNull(state.filter)
        assertEquals(0, state.frameCount)
        assertAnalyzeInvariants(state)
    }

    @Test
    fun `analyzeAction forwards too-many-frames actual and limit`() {
        val decision = EvidenceFrameViewDecision.Reject(
            EvidenceFrameViewRejection.TooManyFrames, actual = 20_001, limit = 20_000
        )
        val state = EvidenceWorkbench.analyzeAction(decision, isAgentRunning = false)

        assertFalse(state.enabled)
        assertEquals(EvidenceAnalyzeBlockReason.TooManyFrames, state.reason)
        assertEquals(20_001, state.actual)
        assertEquals(20_000, state.limit)
        assertAnalyzeInvariants(state)
    }

    @Test
    fun `analyzeAction blocks too many ranges`() {
        val decision = EvidenceFrameViewDecision.Reject(
            EvidenceFrameViewRejection.TooManyRanges, actual = 257, limit = 256
        )
        val state = EvidenceWorkbench.analyzeAction(decision, isAgentRunning = false)

        assertFalse(state.enabled)
        assertEquals(EvidenceAnalyzeBlockReason.TooManyRanges, state.reason)
        assertEquals(257, state.actual)
        assertEquals(256, state.limit)
        assertAnalyzeInvariants(state)
    }

    @Test
    fun `analyzeAction blocks an invalid filter`() {
        val decision = EvidenceFrameViewDecision.Reject(
            EvidenceFrameViewRejection.InvalidFilter, actual = null, limit = null
        )
        val state = EvidenceWorkbench.analyzeAction(decision, isAgentRunning = false)

        assertFalse(state.enabled)
        assertEquals(EvidenceAnalyzeBlockReason.InvalidFilter, state.reason)
        assertNull(state.filter)
        assertAnalyzeInvariants(state)
    }

    @Test
    fun `analyzeAction keeps AgentRunning priority over a rejection`() {
        val decision = EvidenceFrameViewDecision.Reject(
            EvidenceFrameViewRejection.TooManyFrames, actual = 20_001, limit = 20_000
        )
        val state = EvidenceWorkbench.analyzeAction(decision, isAgentRunning = true)

        assertFalse(state.enabled)
        assertEquals(EvidenceAnalyzeBlockReason.AgentRunning, state.reason)
        assertNull(state.filter)
        assertAnalyzeInvariants(state)
    }

    @Test
    fun `analyzeAction greys out an empty evidence set end to end`() {
        val decision = EvidenceFrameViewPolicy.decide(EvidenceFrameFilter.compileOrNull(emptyList()))
        val state = EvidenceWorkbench.analyzeAction(decision, isAgentRunning = false)

        assertFalse(state.enabled)
        assertAnalyzeInvariants(state)
    }

    // EVL-UI-06: evidence-list empty states.

    @Test
    fun `emptyState is None when both all and visible rows are present`() {
        val all = listOf(EvidenceRow(1L, EvidenceSource.Manual, null, null, false))
        val visible = listOf(EvidenceRow(1L, EvidenceSource.Manual, null, null, false))

        assertEquals(EvidenceEmptyState.None, EvidenceWorkbench.emptyState(all, visible))
    }

    @Test
    fun `emptyState is NoEvidence when both all and visible rows are empty`() {
        assertEquals(EvidenceEmptyState.NoEvidence, EvidenceWorkbench.emptyState(emptyList(), emptyList()))
    }

    @Test
    fun `emptyState is GroupEmpty when all rows exist but the visible group is empty`() {
        val all = listOf(EvidenceRow(1L, EvidenceSource.Manual, null, null, false))

        assertEquals(EvidenceEmptyState.GroupEmpty, EvidenceWorkbench.emptyState(all, emptyList()))
    }

    @Test
    fun `emptyState is GroupEmpty when only agent findings back the All group but Manual is selected`() {
        // Only AgentFinding evidence exists, so the All group is non-empty while the
        // Manual group (user-added frames) is empty — the easy-to-misclassify branch.
        val items = listOf(agent(4L, "f1"))
        val findings = listOf(finding("f1", "Resolved title"))
        val allRows = EvidenceWorkbench.rows(items, emptyList(), findings, 10, EvidenceGroup.All)
        val manualRows = EvidenceWorkbench.rows(items, emptyList(), findings, 10, EvidenceGroup.Manual)

        assertTrue(allRows.isNotEmpty())
        assertTrue(manualRows.isEmpty())
        assertEquals(EvidenceEmptyState.GroupEmpty, EvidenceWorkbench.emptyState(allRows, manualRows))
    }

    @Test
    fun `stale frames are not treated as empty and still count toward staleCount`() {
        // Frame 11 in a 10-frame capture is stale but remains a real row.
        val rows = EvidenceWorkbench.rows(listOf(manual(11L)), emptyList(), emptyList(), 10, EvidenceGroup.All)

        assertTrue(rows.isNotEmpty())
        assertEquals(EvidenceEmptyState.None, EvidenceWorkbench.emptyState(emptyList(), rows))
        assertTrue(EvidenceWorkbench.staleCount(rows) > 0)
    }
}
