// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.AgentSavedFinding
import com.example.layanalyzer.model.AnalysisWorkspace
import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.EvidenceSource
import com.example.layanalyzer.model.WorkspaceNote
import com.example.layanalyzer.model.WorkspaceNoteSourceType
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [AnalysisWorkspaceStore] itself reads and writes SharedPreferences and therefore
 * needs an Android Context, so it cannot run in this JVM unit test source set (this
 * module has no Robolectric). These tests instead exercise its persistence codec,
 * [AnalysisWorkspaceCodec], which owns the workspace schema, the legacy
 * `evidenceFrames` -> `evidenceItems` migration and the dual-write compatibility
 * field described in AnalysisWorkspaceStore.kt
 */
class AnalysisWorkspaceStoreTest {

    // -------- Scenario 1: legacy file migration --------

    @Test
    fun `a legacy evidenceFrames only file migrates to ascending manual items`() {
        val json = JSONObject()
            .put("fileFingerprint", "fp-legacy")
            .put("evidenceFrames", JSONArray(listOf(30L, 10L, 20L)))

        val items = AnalysisWorkspaceCodec.decode(json).evidenceItems

        assertEquals(listOf(10L, 20L, 30L), items.map { it.frameNumber })
        items.forEach { item ->
            assertEquals(EvidenceSource.Manual, item.source)
            assertNull(item.sourceFindingId)
            assertEquals(0L, item.addedAtMillis)
        }
    }

    // -------- Scenario 2: full round-trip --------

    @Test
    fun `a workspace round-trips through encode and decode`() {
        val original = AnalysisWorkspace(
            fileFingerprint = "fp-round-trip",
            displayName = "round-trip.pcap",
            analysisConfigVersion = 3,
            displayFilter = "tcp.port == 443",
            selectedFrame = 42L,
            bookmarks = setOf(7L, 1L, 3L),
            notes = listOf(
                WorkspaceNote(frameNumber = 5L, text = "check the handshake", updatedAtMillis = 111L),
                WorkspaceNote(
                    frameNumber = 9L,
                    text = "saved from a finding",
                    updatedAtMillis = 222L,
                    sourceType = WorkspaceNoteSourceType.Agent,
                    sourceId = "finding-9"
                )
            ),
            tags = setOf("tls", "handshake"),
            evidenceItems = listOf(
                item(3L, addedAtMillis = 11L),
                item(8L, EvidenceSource.AgentFinding, sourceFindingId = "finding-9", addedAtMillis = 22L)
            ),
            filterHistory = listOf("http", "dns"),
            favoriteFilters = setOf("tcp"),
            agentFindings = listOf(
                AgentSavedFinding(
                    findingId = "finding-9",
                    title = "Retransmissions",
                    summary = "Repeated retransmits observed",
                    sourceId = "src-1",
                    sourceToolCallIds = listOf("call-1", "call-2"),
                    evidenceFrames = setOf(8L),
                    savedAtMillis = 333L
                )
            )
        )

        assertEquals(original, AnalysisWorkspaceCodec.decode(AnalysisWorkspaceCodec.encode(original)))
    }

    // -------- Scenario 3: dual-write consistency --------

    @Test
    fun `encode dual writes the items and their projected legacy frames`() {
        val subject = workspace(
            evidenceItems = listOf(
                item(20L, EvidenceSource.AgentFinding, sourceFindingId = "finding-20"),
                item(10L)
            )
        )

        val json = AnalysisWorkspaceCodec.encode(subject)

        assertTrue(json.has("evidenceItems"))
        assertTrue(json.has("evidenceFrames"))
        val legacyArray = json.getJSONArray("evidenceFrames")
        val legacyFrames = (0 until legacyArray.length()).map { legacyArray.getLong(it) }
        assertEquals(subject.evidenceFrames.sorted(), legacyFrames)
    }

    // -------- Scenario 4: disagreement tolerance --------

    @Test
    fun `evidenceItems wins when a legacy evidenceFrames array disagrees`() {
        val json = JSONObject()
            .put("fileFingerprint", "fp-disagree")
            .put(
                "evidenceItems",
                JSONArray().put(
                    JSONObject()
                        .put("frameNumber", 5L)
                        .put("source", EvidenceSource.AgentFinding.name)
                        .put("sourceFindingId", "finding-5")
                )
            )
            .put("evidenceFrames", JSONArray(listOf(999L, 1000L)))

        val items = AnalysisWorkspaceCodec.decode(json).evidenceItems

        assertEquals(1, items.size)
        assertEquals(5L, items.single().frameNumber)
        assertEquals(EvidenceSource.AgentFinding, items.single().source)
        assertEquals("finding-5", items.single().sourceFindingId)
    }

    // -------- Scenario 5: unknown-field tolerance --------

    @Test
    fun `unknown top level and item keys are ignored`() {
        val json = JSONObject()
            .put("fileFingerprint", "fp-unknown")
            .put("someFutureTopLevelKey", "ignore-me")
            .put("nestedUnknown", JSONObject().put("a", 1))
            .put(
                "evidenceItems",
                JSONArray().put(
                    JSONObject()
                        .put("frameNumber", 4L)
                        .put("source", EvidenceSource.Manual.name)
                        .put("someFutureItemKey", JSONArray(listOf("x", "y")))
                )
            )

        val items = AnalysisWorkspaceCodec.decode(json).evidenceItems

        assertEquals(1, items.size)
        assertEquals(4L, items.single().frameNumber)
        assertEquals(EvidenceSource.Manual, items.single().source)
        assertNull(items.single().sourceFindingId)
    }

    // -------- Scenario 6: empty set --------

    @Test
    fun `an empty evidenceItems array decodes to an empty list`() {
        val json = JSONObject()
            .put("fileFingerprint", "fp-empty")
            .put("evidenceItems", JSONArray())

        assertTrue(AnalysisWorkspaceCodec.decode(json).evidenceItems.isEmpty())
    }

    @Test
    fun `a file with neither evidence key decodes to an empty list`() {
        val json = JSONObject().put("fileFingerprint", "fp-none")

        assertTrue(AnalysisWorkspaceCodec.decode(json).evidenceItems.isEmpty())
    }

    @Test
    fun `an empty workspace re-encodes to zero length evidence arrays`() {
        val json = AnalysisWorkspaceCodec.encode(workspace())

        assertEquals(0, json.getJSONArray("evidenceItems").length())
        assertEquals(0, json.getJSONArray("evidenceFrames").length())
    }

    // -------- Scenario 7: tolerant item parsing --------

    @Test
    fun `malformed and non positive items are skipped while unknown sources fall back to manual`() {
        val array = JSONArray()
            .put("not-an-object")
            .put(JSONObject().put("frameNumber", -3L))
            .put(JSONObject().put("frameNumber", 0L))
            .put(
                JSONObject()
                    .put("frameNumber", 7L)
                    .put("source", "FromMars")
                    .put("sourceFindingId", "   ")
            )
            .put(
                JSONObject()
                    .put("frameNumber", 9L)
                    .put("source", EvidenceSource.AgentFinding.name)
            )
        val json = JSONObject()
            .put("fileFingerprint", "fp-tolerant")
            .put("evidenceItems", array)

        val items = AnalysisWorkspaceCodec.decode(json).evidenceItems

        assertEquals(listOf(7L, 9L), items.map { it.frameNumber })
        assertEquals(EvidenceSource.Manual, items[0].source)
        assertNull(items[0].sourceFindingId)
        assertEquals(EvidenceSource.AgentFinding, items[1].source)
        assertNull(items[1].sourceFindingId)
    }

    // -------- Scenario 8: derived projection sanity --------

    @Test
    fun `the derived evidenceFrames projection matches the item frame numbers`() {
        val subject = workspace(
            evidenceItems = listOf(
                item(4L),
                item(4L, EvidenceSource.AgentFinding, sourceFindingId = "finding-4"),
                item(9L)
            )
        )

        assertEquals(setOf(4L, 9L), subject.evidenceFrames)
    }

    private fun workspace(
        evidenceItems: List<EvidenceItem> = emptyList()
    ): AnalysisWorkspace = AnalysisWorkspace(
        fileFingerprint = "fingerprint-baseline",
        displayName = "baseline.pcap",
        evidenceItems = evidenceItems
    )

    private fun item(
        frameNumber: Long,
        source: EvidenceSource = EvidenceSource.Manual,
        sourceFindingId: String? = null,
        addedAtMillis: Long = 0L
    ): EvidenceItem = EvidenceItem(
        frameNumber = frameNumber,
        source = source,
        sourceFindingId = sourceFindingId,
        addedAtMillis = addedAtMillis
    )
}
