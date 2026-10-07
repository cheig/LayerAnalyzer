// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.EvidenceExportMode
import com.example.layanalyzer.model.EvidenceExportScope
import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.EvidenceSource
import com.example.layanalyzer.model.WorkspaceNote
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * EVL-EXPORT-03: the provenance fields added to the export manifest.
 *
 * Everything asserted here is pure JVM logic, which is the point of
 * [EvidenceExportManifestFields]: the ViewModel that owns the manifest cannot be
 * instantiated in a JVM test, so the field construction was extracted out of it.
 */
class EvidenceExportManifestFieldsTest {
    private val salt = "test-fingerprint"

    /** A note whose text is fully redactable: an IPv4 address and a host name. */
    private val redactableNote = "src=192.0.2.10 host=api.example.com"

    @Test
    fun `note is passed through unchanged in Original mode`() {
        val items = listOf(EvidenceItem(frameNumber = 7L))
        val notes = listOf(WorkspaceNote(frameNumber = 7L, text = redactableNote, updatedAtMillis = 10L))

        val entry = evidenceItems(EvidenceExportMode.Original, items, notes).getJSONObject(0)

        assertEquals(redactableNote, entry.getString("note"))
    }

    @Test
    fun `note is redacted in Redacted mode`() {
        val items = listOf(EvidenceItem(frameNumber = 7L))
        val notes = listOf(WorkspaceNote(frameNumber = 7L, text = redactableNote, updatedAtMillis = 10L))

        val text = evidenceItems(EvidenceExportMode.Redacted, items, notes)
            .getJSONObject(0)
            .getString("note")

        assertNotEquals(redactableNote, text)
        assertFalse(text.contains("192.0.2.10"))
        assertFalse(text.contains("api.example.com"))
        assertTrue(text.contains("host-"))
    }

    @Test
    fun `note key is omitted in MetadataOnly mode`() {
        val items = listOf(EvidenceItem(frameNumber = 7L))
        val notes = listOf(WorkspaceNote(frameNumber = 7L, text = redactableNote, updatedAtMillis = 10L))

        val entry = evidenceItems(EvidenceExportMode.MetadataOnly, items, notes).getJSONObject(0)

        assertFalse(entry.has("note"))
    }

    @Test
    fun `evidence filter is verbatim in Original mode`() {
        val manifest = manifestFor(EvidenceExportMode.Original, evidenceFilter = "frame.number==7")

        assertEquals("frame.number==7", manifest.getString("evidenceFilter"))
    }

    @Test
    fun `evidence filter is redacted in Redacted mode`() {
        val manifest = manifestFor(EvidenceExportMode.Redacted)

        val filter = manifest.getString("evidenceFilter")
        assertNotEquals(redactableNote, filter)
        assertFalse(filter.contains("api.example.com"))
        assertTrue(filter.contains("host-"))
    }

    @Test
    fun `evidence filter is JSON null in MetadataOnly mode`() {
        val manifest = manifestFor(EvidenceExportMode.MetadataOnly)

        assertTrue(manifest.isNull("evidenceFilter"))
    }

    @Test
    fun `evidence filter is JSON null when no temporary filter applies`() {
        val manifest = manifestFor(
            mode = EvidenceExportMode.Original,
            scope = EvidenceExportScope.CurrentView
        )

        assertTrue(manifest.isNull("evidenceFilter"))
    }

    @Test
    fun `manual evidence carries null sourceFindingId`() {
        val items = listOf(EvidenceItem(frameNumber = 7L, source = EvidenceSource.Manual))

        val entry = evidenceItems(EvidenceExportMode.Original, items).getJSONObject(0)

        assertEquals("Manual", entry.getString("source"))
        assertTrue(entry.isNull("sourceFindingId"))
    }

    @Test
    fun `agent finding evidence passes the finding id through`() {
        val items = listOf(
            EvidenceItem(
                frameNumber = 7L,
                source = EvidenceSource.AgentFinding,
                sourceFindingId = "finding-42"
            )
        )

        val entry = evidenceItems(EvidenceExportMode.Original, items).getJSONObject(0)

        assertEquals("AgentFinding", entry.getString("source"))
        assertEquals("finding-42", entry.getString("sourceFindingId"))
    }

    @Test
    fun `addedAtMillis is passed through unchanged`() {
        val items = listOf(EvidenceItem(frameNumber = 7L, addedAtMillis = 1_700_000_000_123L))

        val entry = evidenceItems(EvidenceExportMode.Original, items).getJSONObject(0)

        assertEquals(1_700_000_000_123L, entry.getLong("addedAtMillis"))
    }

    @Test
    fun `note is joined by frame number`() {
        val items = listOf(
            EvidenceItem(frameNumber = 7L),
            EvidenceItem(frameNumber = 9L)
        )
        val notes = listOf(WorkspaceNote(frameNumber = 7L, text = "note for seven", updatedAtMillis = 1L))

        val array = evidenceItems(EvidenceExportMode.Original, items, notes)

        assertEquals("note for seven", array.getJSONObject(0).getString("note"))
        // Frame 9 has no note: the key must be absent, not an empty string.
        assertFalse(array.getJSONObject(1).has("note"))
    }

    @Test
    fun `a note outside the evidence set does not affect output`() {
        val items = listOf(EvidenceItem(frameNumber = 7L))
        val notes = listOf(
            WorkspaceNote(frameNumber = 7L, text = "kept", updatedAtMillis = 1L),
            WorkspaceNote(frameNumber = 99L, text = "orphan", updatedAtMillis = 2L)
        )

        val array = evidenceItems(EvidenceExportMode.Original, items, notes)

        assertEquals(1, array.length())
        assertEquals("kept", array.getJSONObject(0).getString("note"))
    }

    @Test
    fun `evidence items are sorted ascending regardless of input order`() {
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

        val first = evidenceItems(EvidenceExportMode.Original, ordered)
        val second = evidenceItems(EvidenceExportMode.Original, shuffled)

        assertEquals(first.toString(), second.toString())
        assertEquals(1L, first.getJSONObject(0).getLong("frameNumber"))
        assertEquals(3L, first.getJSONObject(1).getLong("frameNumber"))
        assertEquals(5L, first.getJSONObject(2).getLong("frameNumber"))
    }

    @Test
    fun `empty evidence set yields an empty array`() {
        val array = evidenceItems(EvidenceExportMode.Original, emptyList())

        assertEquals(0, array.length())
        assertEquals(0, EvidenceExportManifestFields.evidenceFrameCount(emptyList()))
    }

    @Test
    fun `evidence frame count de-duplicates frames`() {
        val items = listOf(
            EvidenceItem(frameNumber = 7L),
            EvidenceItem(frameNumber = 7L, source = EvidenceSource.AgentFinding, sourceFindingId = "f"),
            EvidenceItem(frameNumber = 9L)
        )

        assertEquals(2, EvidenceExportManifestFields.evidenceFrameCount(items))
        assertEquals(2, manifestFor(EvidenceExportMode.Original, items = items).getInt("evidenceFrameCount"))
    }

    @Test
    fun `export scope echoes the requested scope`() {
        assertEquals(
            "EvidenceFrames",
            manifestFor(EvidenceExportMode.Original, scope = EvidenceExportScope.EvidenceFrames).getString("exportScope")
        )
        assertEquals(
            "CurrentView",
            manifestFor(EvidenceExportMode.Original, scope = EvidenceExportScope.CurrentView).getString("exportScope")
        )
    }

    @Test
    fun `pcap evidence-only flag follows the export plan`() {
        assertTrue(
            manifestFor(EvidenceExportMode.Original, scope = EvidenceExportScope.EvidenceFrames)
                .getBoolean("pcapIncludesEvidenceFramesOnly")
        )
        assertFalse(
            manifestFor(EvidenceExportMode.Original, scope = EvidenceExportScope.CurrentView)
                .getBoolean("pcapIncludesEvidenceFramesOnly")
        )
        assertFalse(
            manifestFor(EvidenceExportMode.MetadataOnly, scope = EvidenceExportScope.EvidenceFrames)
                .getBoolean("pcapIncludesEvidenceFramesOnly")
        )
    }

    @Test
    fun `redaction without a redactor is refused rather than passed through`() {
        try {
            EvidenceExportManifestFields.evidenceItemsArray(
                items = listOf(EvidenceItem(frameNumber = 7L)),
                notes = listOf(WorkspaceNote(frameNumber = 7L, text = redactableNote, updatedAtMillis = 1L)),
                mode = EvidenceExportMode.Redacted,
                redactor = null
            )
            throw AssertionError("Expected redaction without a redactor to fail closed.")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message.orEmpty().contains("MetadataRedactor"))
        }
    }

    // ---- helpers -------------------------------------------------------------

    private fun manifestFor(
        mode: EvidenceExportMode,
        items: List<EvidenceItem> = listOf(EvidenceItem(frameNumber = 7L)),
        notes: List<WorkspaceNote> = emptyList(),
        scope: EvidenceExportScope = EvidenceExportScope.EvidenceFrames,
        evidenceFilter: String? = redactableNote,
        redactor: MetadataRedactor? = if (mode == EvidenceExportMode.Original) null else MetadataRedactor(salt)
    ): JSONObject = EvidenceExportManifestFields.applyTo(
        manifest = JSONObject(),
        scope = scope,
        plan = EvidenceExportPlanner.planFor(mode, scope),
        evidenceFilter = evidenceFilter,
        items = items,
        notes = notes,
        mode = mode,
        redactor = redactor
    )

    private fun evidenceItems(
        mode: EvidenceExportMode,
        items: List<EvidenceItem>,
        notes: List<WorkspaceNote> = emptyList()
    ): JSONArray = EvidenceExportManifestFields.evidenceItemsArray(
        items = items,
        notes = notes,
        mode = mode,
        redactor = if (mode == EvidenceExportMode.Original) null else MetadataRedactor(salt)
    )
}
