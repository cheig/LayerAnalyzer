// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.EvidenceExportMode
import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.EvidenceSource
import com.example.layanalyzer.model.WorkspaceNote
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * EVL-EXPORT-04: [EvidenceExportManifestFields.provenanceObject], the shared
 * per-frame provenance object used by both the manifest's `evidenceItems` array
 * and each element of `frames.json`.
 *
 * The two call sites must never drift, so the same function builds both; these
 * tests pin its output and assert the delegation directly.
 */
class EvidenceExportProvenanceObjectTest {
    private val salt = "test-fingerprint"

    /** A note whose text is fully redactable: an IPv4 address and a host name. */
    private val redactableNote = "src=192.0.2.10 host=api.example.com"

    @Test
    fun `note is passed through unchanged in Original mode`() {
        val item = EvidenceItem(frameNumber = 7L)
        val note = WorkspaceNote(frameNumber = 7L, text = redactableNote, updatedAtMillis = 10L)

        val entry = provenance(item, note, EvidenceExportMode.Original)

        assertEquals(redactableNote, entry.getString("note"))
    }

    @Test
    fun `note is redacted in Redacted mode`() {
        val item = EvidenceItem(frameNumber = 7L)
        val note = WorkspaceNote(frameNumber = 7L, text = redactableNote, updatedAtMillis = 10L)

        val text = provenance(item, note, EvidenceExportMode.Redacted).getString("note")

        assertNotEquals(redactableNote, text)
        assertFalse(text.contains("192.0.2.10"))
        assertFalse(text.contains("api.example.com"))
        assertTrue(text.contains("host-"))
    }

    @Test
    fun `note key is omitted in MetadataOnly mode`() {
        val item = EvidenceItem(frameNumber = 7L)
        val note = WorkspaceNote(frameNumber = 7L, text = redactableNote, updatedAtMillis = 10L)

        val entry = provenance(item, note, EvidenceExportMode.MetadataOnly)

        assertFalse(entry.has("note"))
    }

    @Test
    fun `note key is omitted when the frame has no note`() {
        val entry = provenance(EvidenceItem(frameNumber = 7L), null, EvidenceExportMode.Original)

        assertFalse(entry.has("note"))
    }

    @Test
    fun `carries frame number source finding id and timestamp`() {
        val item = EvidenceItem(
            frameNumber = 7L,
            source = EvidenceSource.AgentFinding,
            sourceFindingId = "finding-42",
            addedAtMillis = 1_700_000_000_123L
        )

        val entry = provenance(item, null, EvidenceExportMode.Original)

        assertEquals(7L, entry.getLong("frameNumber"))
        assertEquals("AgentFinding", entry.getString("source"))
        assertEquals("finding-42", entry.getString("sourceFindingId"))
        assertEquals(1_700_000_000_123L, entry.getLong("addedAtMillis"))
    }

    @Test
    fun `manual evidence carries null sourceFindingId`() {
        val entry = provenance(EvidenceItem(frameNumber = 7L), null, EvidenceExportMode.Original)

        assertTrue(entry.isNull("sourceFindingId"))
    }

    @Test
    fun `redaction without a redactor is refused rather than passed through`() {
        val item = EvidenceItem(frameNumber = 7L)
        val note = WorkspaceNote(frameNumber = 7L, text = redactableNote, updatedAtMillis = 1L)

        try {
            EvidenceExportManifestFields.provenanceObject(
                item = item,
                note = note,
                mode = EvidenceExportMode.Redacted,
                redactor = null
            )
            throw AssertionError("Expected redaction without a redactor to fail closed.")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message.orEmpty().contains("MetadataRedactor"))
        }
    }

    @Test
    fun `manifest entry and provenance object are byte-identical for the same frame`() {
        val item = EvidenceItem(
            frameNumber = 7L,
            source = EvidenceSource.AgentFinding,
            sourceFindingId = "finding-42",
            addedAtMillis = 5L
        )
        val notes = listOf(WorkspaceNote(frameNumber = 7L, text = redactableNote, updatedAtMillis = 1L))

        val manifestEntry = EvidenceExportManifestFields.evidenceItemsArray(
            items = listOf(item),
            notes = notes,
            mode = EvidenceExportMode.Original,
            redactor = null
        ).getJSONObject(0)

        assertEquals(
            manifestEntry.toString(),
            provenance(item, notes.first(), EvidenceExportMode.Original).toString()
        )
    }

    @Test
    fun `manifest entry and provenance object are byte-identical when the frame has no note`() {
        val item = EvidenceItem(frameNumber = 7L)

        val manifestEntry = EvidenceExportManifestFields.evidenceItemsArray(
            items = listOf(item),
            notes = emptyList(),
            mode = EvidenceExportMode.Original,
            redactor = null
        ).getJSONObject(0)

        assertEquals(
            manifestEntry.toString(),
            provenance(item, null, EvidenceExportMode.Original).toString()
        )
    }

    // ---- helpers -------------------------------------------------------------

    private fun provenance(
        item: EvidenceItem,
        note: WorkspaceNote?,
        mode: EvidenceExportMode
    ): JSONObject = EvidenceExportManifestFields.provenanceObject(
        item = item,
        note = note,
        mode = mode,
        redactor = if (mode == EvidenceExportMode.Original) null else MetadataRedactor(salt)
    )
}
