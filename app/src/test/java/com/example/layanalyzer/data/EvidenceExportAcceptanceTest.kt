// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.AgentSavedFinding
import com.example.layanalyzer.model.EvidenceExportMode
import com.example.layanalyzer.model.EvidenceExportMode.MetadataOnly
import com.example.layanalyzer.model.EvidenceExportMode.Original
import com.example.layanalyzer.model.EvidenceExportMode.Redacted
import com.example.layanalyzer.model.EvidenceExportScope
import com.example.layanalyzer.model.EvidenceExportScope.CurrentView
import com.example.layanalyzer.model.EvidenceExportScope.EvidenceFrames
import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.EvidenceSource
import com.example.layanalyzer.model.WorkspaceNote
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipFile

/**
 * Acceptance-level combination coverage for the evidence-frame export flow
 * (EVL-EXPORT-05). The unit tests of EVL-EXPORT-01..04 pin each pure function
 * in isolation; this file wires them together in the order the real export
 * flow uses — plan -> compile -> policy/manifest/report -> package writer —
 * and asserts the end-to-end contracts that only appear across components:
 *
 * A. the full (mode x scope) matrix on one shared fixture;
 * B. the empty-set path mirroring the UI's greyed-out semantics;
 * C. the over-limit rejection path (fail-closed, no silent truncation);
 * D. frame-count consistency, including a real zip round trip through
 *    [EvidencePackageWriter].
 *
 * Everything here runs on the JVM against the pure data layer only; the
 * ViewModel that drives these calls needs a Context and is out of scope.
 */
class EvidenceExportAcceptanceTest {

    // --- shared fixtures ---------------------------------------------------

    private val finding = AgentSavedFinding(
        findingId = "finding-1",
        title = "TLS handshake reset",
        summary = "peer reset the handshake",
        sourceId = "tool-call-1",
        savedAtMillis = 1_000L
    )

    /** Five entries over four distinct frames — frame 5 is deliberately duplicated. */
    private fun evidenceItems(): List<EvidenceItem> = listOf(
        EvidenceItem(3L, EvidenceSource.Manual, null, 100L),
        EvidenceItem(5L, EvidenceSource.AgentFinding, "finding-1", 200L),
        EvidenceItem(6L, EvidenceSource.Manual, null, 300L),
        EvidenceItem(100L, EvidenceSource.Manual, null, 400L),
        EvidenceItem(5L, EvidenceSource.Manual, null, 500L)
    )

    /** Note text carries a real IPv4 so the Redacted mode visibly changes it. */
    private fun workspaceNotes(): List<WorkspaceNote> = listOf(
        WorkspaceNote(5L, "server 192.0.2.10 sent RST", 900L),
        WorkspaceNote(100L, "client 192.0.2.99 retried", 910L)
    )

    private fun findings(): List<AgentSavedFinding> = listOf(finding)

    /**
     * The filter the shared fixture compiles to: three merged ranges over the
     * four distinct frames {3, 5, 6, 100}.
     */
    private val expectedFilter =
        "frame.number==3 || (frame.number>=5 && frame.number<=6) || frame.number==100"

    private class Pipeline(
        val plan: com.example.layanalyzer.data.EvidenceExportPlan,
        val compile: EvidenceFrameFilter.CompileResult,
        val manifest: JSONObject,
        val report: String,
        val redactor: MetadataRedactor
    )

    /** Runs the real export chain for one (mode, scope) pair on the shared fixture. */
    private fun runPipeline(mode: EvidenceExportMode, scope: EvidenceExportScope): Pipeline {
        val redactor = MetadataRedactor("acceptance-salt")
        val items = evidenceItems()
        val notes = workspaceNotes()
        val compile = EvidenceFrameFilter.compileOrNull(items.map { it.frameNumber })
        val compiledFilter = (compile as? EvidenceFrameFilter.CompileResult.Compiled)?.filter
        val plan = EvidenceExportPlanner.planFor(mode, scope)
        val manifest = EvidenceExportManifestFields.applyTo(
            JSONObject(),
            scope,
            plan,
            // Only an actually-applied filter is reported; CurrentView never applies one.
            if (plan.applyEvidenceTemporaryFilter) compiledFilter else null,
            items,
            notes,
            mode,
            redactor
        )
        val report = EvidenceExportReportSections.evidenceFramesTable(
            items, notes, findings(), mode, redactor
        )
        return Pipeline(plan, compile, manifest, report, redactor)
    }

    /** Same chain as [runPipeline] but on an empty evidence set. */
    private fun runEmptyPipeline(mode: EvidenceExportMode, scope: EvidenceExportScope): Pipeline {
        val redactor = MetadataRedactor("acceptance-salt")
        val plan = EvidenceExportPlanner.planFor(mode, scope)
        val manifest = EvidenceExportManifestFields.applyTo(
            JSONObject(), scope, plan, null, emptyList(), emptyList(), mode, redactor
        )
        val report = EvidenceExportReportSections.evidenceFramesTable(
            emptyList(), emptyList(), emptyList(), mode, redactor
        )
        return Pipeline(plan, EvidenceFrameFilter.compileOrNull(emptyList()), manifest, report, redactor)
    }

    private fun itemOf(items: JSONArray, frameNumber: Long): JSONObject {
        for (i in 0 until items.length()) {
            val entry = items.getJSONObject(i)
            if (entry.getLong("frameNumber") == frameNumber) return entry
        }
        throw AssertionError("No evidence item for frame $frameNumber")
    }

    private fun manifestFrameNumbers(manifest: JSONObject): Set<Long> {
        val items = manifest.getJSONArray(EvidenceExportManifestFields.KEY_EVIDENCE_ITEMS)
        return (0 until items.length()).map { items.getJSONObject(it).getLong("frameNumber") }.toSet()
    }

    private val ROW_FRAME = Regex("^\\| (\\d+) \\|")

    private fun tableFrameNumbers(report: String): Set<Long> =
        report.lines().mapNotNull { line -> ROW_FRAME.find(line)?.groupValues?.get(1)?.toLong() }.toSet()

    /** The report table and the manifest items must describe the same frame set. */
    private fun assertTableMatchesManifest(pipeline: Pipeline) {
        assertTrue(pipeline.report.contains("| 帧号 |"))
        assertEquals(manifestFrameNumbers(pipeline.manifest), tableFrameNumbers(pipeline.report))
    }

    // --- A. three modes x two scopes ---------------------------------------

    @Test
    fun `original with EvidenceFrames attaches an evidence-only pcap with verbatim filter and notes`() {
        val pipeline = runPipeline(Original, EvidenceFrames)

        assertTrue(pipeline.plan.attachCapture)
        assertTrue(pipeline.plan.applyEvidenceTemporaryFilter)
        assertTrue(pipeline.plan.verifyEvidenceFrameCount)
        assertTrue(pipeline.plan.pcapIncludesEvidenceFramesOnly)

        val manifest = pipeline.manifest
        assertEquals("EvidenceFrames", manifest.getString(EvidenceExportManifestFields.KEY_EXPORT_SCOPE))
        assertEquals(expectedFilter, manifest.getString(EvidenceExportManifestFields.KEY_EVIDENCE_FILTER))
        assertEquals(4, manifest.getInt(EvidenceExportManifestFields.KEY_EVIDENCE_FRAME_COUNT))
        assertTrue(manifest.getBoolean(EvidenceExportManifestFields.KEY_PCAP_EVIDENCE_ONLY))

        val items = manifest.getJSONArray(EvidenceExportManifestFields.KEY_EVIDENCE_ITEMS)
        assertEquals("server 192.0.2.10 sent RST", itemOf(items, 5L).getString("note"))
        assertEquals("client 192.0.2.99 retried", itemOf(items, 100L).getString("note"))
        assertFalse(itemOf(items, 3L).has("note"))

        assertTableMatchesManifest(pipeline)
    }

    @Test
    fun `redacted with EvidenceFrames keeps the filter verbatim and redacts note text`() {
        val pipeline = runPipeline(Redacted, EvidenceFrames)

        assertFalse(pipeline.plan.attachCapture)
        assertTrue(pipeline.plan.applyEvidenceTemporaryFilter)
        assertFalse(pipeline.plan.pcapIncludesEvidenceFramesOnly)

        val manifest = pipeline.manifest
        assertEquals("EvidenceFrames", manifest.getString(EvidenceExportManifestFields.KEY_EXPORT_SCOPE))
        // The compiled filter only contains digits and the frame.number syntax. No
        // token in it has an IP/MAC/host/subscriber shape, and "frame.number" is a
        // reserved dotted name (its TLD is not a public suffix), so the redactor
        // passes the expression through byte-for-byte. Pinned here explicitly.
        assertEquals(expectedFilter, pipeline.redactor.redact(expectedFilter))
        assertEquals(expectedFilter, manifest.getString(EvidenceExportManifestFields.KEY_EVIDENCE_FILTER))

        val items = manifest.getJSONArray(EvidenceExportManifestFields.KEY_EVIDENCE_ITEMS)
        // Redaction is deterministic per salt, so a fresh redactor yields the same alias.
        val expectedNote = MetadataRedactor("acceptance-salt").redact("server 192.0.2.10 sent RST")
        val note5 = itemOf(items, 5L).getString("note")
        assertEquals(expectedNote, note5)
        assertNotEquals("server 192.0.2.10 sent RST", note5)
        assertFalse(note5.contains("192.0.2"))
        assertFalse(itemOf(items, 100L).getString("note").contains("192.0.2"))

        assertTableMatchesManifest(pipeline)
    }

    @Test
    fun `metadataOnly with EvidenceFrames nulls the filter and omits every note key`() {
        val pipeline = runPipeline(MetadataOnly, EvidenceFrames)

        assertTrue(pipeline.plan.applyEvidenceTemporaryFilter)
        assertFalse(pipeline.plan.pcapIncludesEvidenceFramesOnly)

        val manifest = pipeline.manifest
        assertEquals("EvidenceFrames", manifest.getString(EvidenceExportManifestFields.KEY_EXPORT_SCOPE))
        // The mode forbids filter text even though one was compiled and applied.
        assertEquals(
            JSONObject.NULL,
            manifest.get(EvidenceExportManifestFields.KEY_EVIDENCE_FILTER)
        )

        val items = manifest.getJSONArray(EvidenceExportManifestFields.KEY_EVIDENCE_ITEMS)
        for (i in 0 until items.length()) {
            assertFalse("note key must be omitted entirely", items.getJSONObject(i).has("note"))
        }

        assertTableMatchesManifest(pipeline)
    }

    @Test
    fun `original with CurrentView keeps raw notes and reports no evidence filter`() {
        val pipeline = runPipeline(Original, CurrentView)

        assertTrue(pipeline.plan.attachCapture)
        assertFalse(pipeline.plan.applyEvidenceTemporaryFilter)
        assertFalse(pipeline.plan.verifyEvidenceFrameCount)
        assertFalse(pipeline.plan.pcapIncludesEvidenceFramesOnly)

        val manifest = pipeline.manifest
        assertEquals("CurrentView", manifest.getString(EvidenceExportManifestFields.KEY_EXPORT_SCOPE))
        // No evidence filter was applied, so reporting one would be a lie.
        assertEquals(
            JSONObject.NULL,
            manifest.get(EvidenceExportManifestFields.KEY_EVIDENCE_FILTER)
        )

        val items = manifest.getJSONArray(EvidenceExportManifestFields.KEY_EVIDENCE_ITEMS)
        assertEquals("server 192.0.2.10 sent RST", itemOf(items, 5L).getString("note"))
        assertEquals("client 192.0.2.99 retried", itemOf(items, 100L).getString("note"))

        assertTableMatchesManifest(pipeline)
    }

    @Test
    fun `redacted with CurrentView nulls the evidence filter and redacts note text`() {
        val pipeline = runPipeline(Redacted, CurrentView)

        assertFalse(pipeline.plan.attachCapture)
        assertFalse(pipeline.plan.applyEvidenceTemporaryFilter)
        assertFalse(pipeline.plan.pcapIncludesEvidenceFramesOnly)

        val manifest = pipeline.manifest
        assertEquals("CurrentView", manifest.getString(EvidenceExportManifestFields.KEY_EXPORT_SCOPE))
        assertEquals(
            JSONObject.NULL,
            manifest.get(EvidenceExportManifestFields.KEY_EVIDENCE_FILTER)
        )

        val items = manifest.getJSONArray(EvidenceExportManifestFields.KEY_EVIDENCE_ITEMS)
        assertFalse(itemOf(items, 5L).getString("note").contains("192.0.2"))

        assertTableMatchesManifest(pipeline)
    }

    @Test
    fun `metadataOnly with CurrentView nulls the filter and omits note keys`() {
        val pipeline = runPipeline(MetadataOnly, CurrentView)

        assertFalse(pipeline.plan.attachCapture)
        assertFalse(pipeline.plan.applyEvidenceTemporaryFilter)
        assertFalse(pipeline.plan.pcapIncludesEvidenceFramesOnly)

        val manifest = pipeline.manifest
        assertEquals("CurrentView", manifest.getString(EvidenceExportManifestFields.KEY_EXPORT_SCOPE))
        assertEquals(
            JSONObject.NULL,
            manifest.get(EvidenceExportManifestFields.KEY_EVIDENCE_FILTER)
        )

        val items = manifest.getJSONArray(EvidenceExportManifestFields.KEY_EVIDENCE_ITEMS)
        for (i in 0 until items.length()) {
            assertFalse(items.getJSONObject(i).has("note"))
        }

        assertTableMatchesManifest(pipeline)
    }

    @Test
    fun `pcapIncludesEvidenceFramesOnly is true only for Original combined with EvidenceFrames`() {
        for (mode in listOf(Original, Redacted, MetadataOnly)) {
            for (scope in listOf(EvidenceFrames, CurrentView)) {
                val plan = EvidenceExportPlanner.planFor(mode, scope)
                assertEquals(
                    "mode=$mode scope=$scope",
                    mode == Original && scope == EvidenceFrames,
                    plan.pcapIncludesEvidenceFramesOnly
                )
            }
        }
    }

    // --- B. empty evidence set (mirrors the UI greyed-out semantics) --------

    @Test
    fun `empty evidence set is unavailable for EvidenceFrames and renders no table for either scope`() {
        val compile = EvidenceFrameFilter.compileOrNull(emptyList())
        assertTrue(compile is EvidenceFrameFilter.CompileResult.Empty)

        // EvidenceFrames: unavailable, mirroring the greyed-out UI entry.
        val evidenceAvailability = EvidenceExportScopePolicy.evaluate(EvidenceFrames, compile)
        assertFalse(evidenceAvailability.available)
        assertEquals(
            EvidenceExportScopePolicy.ReasonCode.NoEvidenceFrames,
            evidenceAvailability.reasonCode
        )

        // CurrentView: always available, but it still must not fabricate evidence rows.
        val currentAvailability = EvidenceExportScopePolicy.evaluate(CurrentView, compile)
        assertTrue(currentAvailability.available)

        for (mode in listOf(Original, Redacted, MetadataOnly)) {
            for (scope in listOf(EvidenceFrames, CurrentView)) {
                val pipeline = runEmptyPipeline(mode, scope)
                assertEquals(
                    EvidenceExportReportSections.NO_EVIDENCE_FRAMES,
                    pipeline.report
                )
                assertFalse("no table header may appear", pipeline.report.contains("| 帧号"))
            }
        }
    }

    @Test
    fun `empty evidence set manifest carries an empty items array, zero count and a null filter`() {
        for (scope in listOf(EvidenceFrames, CurrentView)) {
            val plan = EvidenceExportPlanner.planFor(Original, scope)
            val manifest = EvidenceExportManifestFields.applyTo(
                JSONObject(), scope, plan, null, emptyList(), emptyList(), Original,
                MetadataRedactor("acceptance-salt")
            )
            // An empty array, not JSON null: consumers may iterate unconditionally.
            assertTrue(manifest.has(EvidenceExportManifestFields.KEY_EVIDENCE_ITEMS))
            assertFalse(manifest.get(EvidenceExportManifestFields.KEY_EVIDENCE_ITEMS) === JSONObject.NULL)
            assertEquals(
                0,
                manifest.getJSONArray(EvidenceExportManifestFields.KEY_EVIDENCE_ITEMS).length()
            )
            assertEquals(0, manifest.getInt(EvidenceExportManifestFields.KEY_EVIDENCE_FRAME_COUNT))
            // Even though the EvidenceFrames plan would apply a filter, the compile
            // produced none — the manifest reports null rather than inventing a value.
            assertEquals(
                JSONObject.NULL,
                manifest.get(EvidenceExportManifestFields.KEY_EVIDENCE_FILTER)
            )
        }
    }

    // --- C. over-limit rejection path (fail-closed) --------------------------

    private fun overRangeFrames(): List<Long> = (0L until 260L).map { it * 2L + 1L }

    @Test
    fun `more than MAX_RANGES ranges rejects the whole compilation without any filter`() {
        val result = EvidenceFrameFilter.compileOrNull(overRangeFrames())
        val rejected = result as EvidenceFrameFilter.CompileResult.Rejected

        assertEquals(EvidenceFrameFilter.RejectReason.TooManyRanges, rejected.reason)
        assertEquals(260, rejected.actual)
        assertEquals(EvidenceFrameFilter.MAX_RANGES, rejected.limit)
        // Fail-closed: the rejection message names the limit, never a partial filter.
        assertTrue(rejected.message.contains("nothing was compiled"))
        assertFalse(rejected.message.contains("frame.number"))
    }

    @Test
    fun `rejected compilation makes the evidence scope unavailable and exposes the limit fields`() {
        val rejected = EvidenceFrameFilter.compileOrNull(overRangeFrames())
        val availability = EvidenceExportScopePolicy.evaluate(EvidenceFrames, rejected)

        assertFalse(availability.available)
        assertEquals(
            EvidenceExportScopePolicy.ReasonCode.FilterRejected,
            availability.reasonCode
        )
        assertEquals(260, availability.actual)
        assertEquals(EvidenceFrameFilter.MAX_RANGES, availability.limit)
        assertEquals(EvidenceFrameFilter.RejectReason.TooManyRanges, availability.rejectReason)
    }

    @Test
    fun `range and frame limits accept the exact boundary and reject one above it`() {
        // 256 non-adjacent frames -> exactly MAX_RANGES ranges -> accepted.
        val atRangeLimit = EvidenceFrameFilter.compileOrNull((0L until 256L).map { it * 2L + 1L })
            as EvidenceFrameFilter.CompileResult.Compiled
        assertEquals(256, atRangeLimit.rangeCount)
        assertEquals(256, atRangeLimit.frameCount)

        // 20000 contiguous frames -> exactly MAX_FRAMES frames, one range -> accepted.
        val atFrameLimit = EvidenceFrameFilter.compileOrNull((1L..20000L).toList())
            as EvidenceFrameFilter.CompileResult.Compiled
        assertEquals(20000, atFrameLimit.frameCount)
        assertEquals(1, atFrameLimit.rangeCount)

        // One frame above the cap -> rejected as a whole, never truncated.
        val overFrameLimit = EvidenceFrameFilter.compileOrNull((1L..20001L).toList())
            as EvidenceFrameFilter.CompileResult.Rejected
        assertEquals(EvidenceFrameFilter.RejectReason.TooManyFrames, overFrameLimit.reason)
        assertEquals(20001, overFrameLimit.actual)
        assertEquals(EvidenceFrameFilter.MAX_FRAMES, overFrameLimit.limit)
    }

    @Test
    fun `a manifest built on a rejected compile never carries any partial filter`() {
        val rejected = EvidenceFrameFilter.compileOrNull(overRangeFrames())
        // The only filter a manifest may record is a Compiled one; a rejection
        // yields null, so nothing of the refused set can leak into report.json.
        assertNull((rejected as? EvidenceFrameFilter.CompileResult.Compiled)?.filter)

        val plan = EvidenceExportPlanner.planFor(Original, EvidenceFrames)
        val manifest = EvidenceExportManifestFields.applyTo(
            JSONObject(), EvidenceFrames, plan, null, evidenceItems(), emptyList(),
            Original, MetadataRedactor("acceptance-salt")
        )
        assertEquals(
            JSONObject.NULL,
            manifest.get(EvidenceExportManifestFields.KEY_EVIDENCE_FILTER)
        )
        assertFalse(manifest.toString().contains("frame.number"))
    }

    // --- D. frame-count consistency, including a real zip round trip ---------

    @Test
    fun `evidenceFrameCount and compiled frameCount agree on the de-duplicated size`() {
        val items = evidenceItems()
        val frames = items.map { it.frameNumber }
        val compiled = EvidenceFrameFilter.compileOrNull(frames)
            as EvidenceFrameFilter.CompileResult.Compiled

        assertEquals(4, compiled.frameCount)
        assertEquals(compiled.frameCount, EvidenceExportManifestFields.evidenceFrameCount(items))
        assertEquals(frames.toSet().size, EvidenceExportManifestFields.evidenceFrameCount(items))
    }

    @Test
    fun `frame count guard matches only equal positive counts and carries both numbers on mismatch`() {
        assertTrue(EvidenceFrameCountGuard.verify(4, 4) is EvidenceFrameCountVerification.Match)

        val fewer = EvidenceFrameCountGuard.verify(4, 3)
            as EvidenceFrameCountVerification.Mismatch
        assertEquals(4, fewer.expected)
        assertEquals(3, fewer.actual)

        val more = EvidenceFrameCountGuard.verify(4, 5)
            as EvidenceFrameCountVerification.Mismatch
        assertEquals(4, more.expected)
        assertEquals(5, more.actual)

        // Fail-closed by design: a zero expectation never passes, even against zero.
        assertTrue(EvidenceFrameCountGuard.verify(0, 0) is EvidenceFrameCountVerification.Mismatch)
    }

    @Test
    fun `written evidence package keeps counts, provenance, capture and table consistent`() {
        val redactor = MetadataRedactor("acceptance-salt")
        // De-duplicated on purpose so the manifest item count equals the frame count.
        val items = evidenceItems().distinctBy { it.frameNumber }
        val notes = workspaceNotes()
        val frames = items.map { it.frameNumber }
        val compiled = EvidenceFrameFilter.compileOrNull(frames)
            as EvidenceFrameFilter.CompileResult.Compiled
        val plan = EvidenceExportPlanner.planFor(Original, EvidenceFrames)
        val manifest = EvidenceExportManifestFields.applyTo(
            JSONObject(), EvidenceFrames, plan, compiled.filter, items, notes, Original, redactor
        )

        val framesJson = JSONArray()
        for (item in items) {
            val note = notes.firstOrNull { it.frameNumber == item.frameNumber }
            framesJson.put(
                JSONObject()
                    .put("frameNumber", item.frameNumber)
                    .put(
                        "provenance",
                        EvidenceExportManifestFields.provenanceObject(item, note, Original, redactor)
                    )
            )
        }
        val report = EvidenceExportReportSections.evidenceFramesTable(
            items, notes, findings(), Original, redactor
        )

        val capture = File.createTempFile("capture", ".pcap")
            .apply { writeBytes(byteArrayOf(0xd4.toByte(), 0xc3.toByte(), 0xb2.toByte(), 0xa1.toByte(), 1, 0, 0, 0)) }
        val output = File.createTempFile("evidence", ".zip")
        try {
            EvidencePackageWriter().write(
                output, manifest.toString(), report, framesJson.toString(), capture
            )
            ZipFile(output).use { zip ->
                val storedManifest = JSONObject(
                    zip.getInputStream(zip.getEntry("report.json")).readBytes().toString(Charsets.UTF_8)
                )
                val storedFrames = JSONArray(
                    zip.getInputStream(zip.getEntry("frames.json")).readBytes().toString(Charsets.UTF_8)
                )
                val storedReport = zip.getInputStream(zip.getEntry("report.md"))
                    .readBytes().toString(Charsets.UTF_8)

                // One number, four places: the manifest count, the compiled count,
                // the frames.json array length and the evidenceItems length.
                val count = storedManifest.getInt(EvidenceExportManifestFields.KEY_EVIDENCE_FRAME_COUNT)
                assertEquals(compiled.frameCount, count)
                assertEquals(count, storedFrames.length())
                assertEquals(
                    count,
                    storedManifest.getJSONArray(EvidenceExportManifestFields.KEY_EVIDENCE_ITEMS).length()
                )

                // Provenance parity: each frames.json element matches the manifest
                // entry for the same frame number.
                val manifestItems = storedManifest
                    .getJSONArray(EvidenceExportManifestFields.KEY_EVIDENCE_ITEMS)
                val byFrame = HashMap<Long, JSONObject>()
                for (i in 0 until manifestItems.length()) {
                    val entry = manifestItems.getJSONObject(i)
                    byFrame[entry.getLong("frameNumber")] = entry
                }
                for (i in 0 until storedFrames.length()) {
                    val frame = storedFrames.getJSONObject(i)
                    // JSONObject is reference-equal by default; use similar() for
                    // content comparison across independently parsed objects.
                    val provenance = frame.getJSONObject("provenance")
                    val manifestEntry = byFrame[frame.getLong("frameNumber")]
                    assertTrue(
                        "provenance mismatch for frame ${frame.getLong("frameNumber")}",
                        manifestEntry!!.similar(provenance)
                    )
                }

                // The capture survives the round trip byte for byte.
                val captureEntry = zip.getEntry("capture/${capture.name}")
                assertTrue(captureEntry != null)
                assertArrayEquals(capture.readBytes(), zip.getInputStream(captureEntry).readBytes())

                // The report table has a header and one row per evidence frame,
                // covering exactly the manifest frame set.
                assertTrue(storedReport.contains("| 帧号 |"))
                assertEquals(frames.toSet(), tableFrameNumbers(storedReport))
            }
        } finally {
            capture.delete()
            output.delete()
        }
    }

    @Test
    fun `package with an empty evidence set writes the no-evidence sentence and no frames`() {
        val redactor = MetadataRedactor("acceptance-salt")
        val plan = EvidenceExportPlanner.planFor(MetadataOnly, EvidenceFrames)
        val manifest = EvidenceExportManifestFields.applyTo(
            JSONObject(), EvidenceFrames, plan, null, emptyList(), emptyList(), MetadataOnly, redactor
        )
        val report = EvidenceExportReportSections.evidenceFramesTable(
            emptyList(), emptyList(), emptyList(), MetadataOnly, redactor
        )

        val output = File.createTempFile("evidence", ".zip")
        try {
            EvidencePackageWriter().write(output, manifest.toString(), report, "[]")
            ZipFile(output).use { zip ->
                val storedManifest = JSONObject(
                    zip.getInputStream(zip.getEntry("report.json")).readBytes().toString(Charsets.UTF_8)
                )
                val storedReport = zip.getInputStream(zip.getEntry("report.md"))
                    .readBytes().toString(Charsets.UTF_8)

                assertEquals(0, storedManifest.getInt(EvidenceExportManifestFields.KEY_EVIDENCE_FRAME_COUNT))
                assertEquals(
                    0,
                    storedManifest.getJSONArray(EvidenceExportManifestFields.KEY_EVIDENCE_ITEMS).length()
                )
                assertEquals(EvidenceExportReportSections.NO_EVIDENCE_FRAMES, storedReport)
                assertEquals(0, JSONArray(
                    zip.getInputStream(zip.getEntry("frames.json")).readBytes().toString(Charsets.UTF_8)
                ).length())
                assertFalse(zip.entries().asSequence().any { it.name.startsWith("capture/") })
            }
        } finally {
            output.delete()
        }
    }
}
