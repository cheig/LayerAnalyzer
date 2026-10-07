// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * EVL-CONTEXT-04: the pure decisions that keep an evidence display-filter
 * override consistent with what the user sees — whether the packet list must
 * be re-framed when the run starts, and which frame count the report page
 * renders as "Analysis scope: evidence set (N frames)".  Also pins the
 * provenance field's JSON round-trip: emitted only when set, absent for
 * legacy reports, never invented.
 */
class AgentEvidenceScopeTest {

    // --------------------------------- packet-list application decision

    @Test
    fun aNullOverrideNeverTouchesThePacketList() {
        assertEquals(false, AgentEvidenceScope.shouldApplyOverrideToPacketList(null, "tcp"))
        assertEquals(false, AgentEvidenceScope.shouldApplyOverrideToPacketList(null, null))
    }

    @Test
    fun aBlankOverrideNeverTouchesThePacketList() {
        assertEquals(false, AgentEvidenceScope.shouldApplyOverrideToPacketList("", "tcp"))
        assertEquals(false, AgentEvidenceScope.shouldApplyOverrideToPacketList("   ", "tcp"))
    }

    @Test
    fun aUsableOverrideDifferentFromTheAppliedFilterIsApplied() {
        assertEquals(
            true,
            AgentEvidenceScope.shouldApplyOverrideToPacketList("frame.number==5", "tcp")
        )
        assertEquals(
            true,
            AgentEvidenceScope.shouldApplyOverrideToPacketList("frame.number==5", null)
        )
        assertEquals(
            true,
            AgentEvidenceScope.shouldApplyOverrideToPacketList("frame.number==5", "")
        )
    }

    @Test
    fun anOverrideIdenticalToTheAppliedFilterIsNotReapplied() {
        assertEquals(
            false,
            AgentEvidenceScope.shouldApplyOverrideToPacketList("tcp", "tcp")
        )
        // Trimming is not a difference.
        assertEquals(
            false,
            AgentEvidenceScope.shouldApplyOverrideToPacketList("  tcp  ", "tcp")
        )
    }

    // ----------------------------------------- report frame count decision

    @Test
    fun noOverrideHidesTheReportScopeLine() {
        assertNull(AgentEvidenceScope.reportFrameCount(null, 42))
        assertNull(AgentEvidenceScope.reportFrameCount("", 42))
        assertNull(AgentEvidenceScope.reportFrameCount("   ", 42))
    }

    @Test
    fun anOverrideWithoutARecordedCountHidesTheReportScopeLine() {
        assertNull(AgentEvidenceScope.reportFrameCount("frame.number==5", null))
    }

    @Test
    fun anEmptyEvidenceSetHidesTheReportScopeLine() {
        // An empty evidence set cannot start an evidence run; a zero count is
        // never rendered as if a real set was analyzed.
        assertNull(AgentEvidenceScope.reportFrameCount("frame.number==5", 0))
    }

    @Test
    fun anOverrideWithARecordedCountRendersThatCount() {
        assertEquals(42, AgentEvidenceScope.reportFrameCount("frame.number==5", 42))
    }

    // ------------------------------------------------- provenance JSON contract

    @Test
    fun theEvidenceFrameCountRoundTripsThroughTheReportCodec() {
        val report = AgentReport(
            summary = "Evidence-framed run.",
            provenance = AgentReportProvenance(
                displayFilter = "frame.number==5",
                evidenceFrameCount = 12
            )
        )
        val decoded = AgentJsonCodec.decodeReport(AgentJsonCodec.encodeReport(report)).getOrThrow()
        assertEquals("frame.number==5", decoded.provenance.displayFilter)
        assertEquals(12, decoded.provenance.evidenceFrameCount)
    }

    @Test
    fun aLegacyProvenanceWithoutTheFieldDecodesAsNull() {
        val legacy = AgentReport(
            summary = "No evidence workflow.",
            provenance = AgentReportProvenance(displayFilter = "tcp")
        )
        val encoded = JSONObject(AgentJsonCodec.encodeReport(legacy))
        assertEquals(
            false,
            encoded.getJSONObject("provenance").has("evidenceFrameCount")
        )
        val decoded = AgentJsonCodec.decodeReport(encoded.toString()).getOrThrow()
        assertNull(decoded.provenance.evidenceFrameCount)
    }
}
