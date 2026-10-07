// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentAnalysisPlan
import com.example.layanalyzer.model.AgentAnalysisPlanStep
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingPolarity
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentProvenance
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.AnalysisScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EvidenceValidatorTest {

    // ------------------------------------------------------ reference integrity

    @Test
    fun evidenceCitingAnUnknownToolCallIsRemoved() {
        val ledger = ledgerWith(
            call("call-overview", "get_capture_overview", data = mapOf("frameCount" to 10))
        )
        val report = reportWith(
            evidence(sourceToolCallId = "call-never-ran", type = AgentEvidenceType.ExpertInfo)
        )

        val result = validate(report, ledger)

        assertTrue(result.report.findings.single().evidence.isEmpty())
        assertTrue(result.rejections.any { it.reason == "unknown_source" })
        assertTrue(result.report.limitations.any { it.contains("call-never-ran") })
    }

    @Test
    fun fabricatedFrameNumberIsRemoved() {
        val ledger = ledgerWith(
            call(
                "call-expert",
                "get_expert_info",
                data = mapOf("items" to listOf(mapOf("frameNumber" to 7L)))
            )
        )
        val report = reportWith(
            evidence(sourceToolCallId = "call-expert", frameNumber = 4_242L)
        )

        val result = validate(report, ledger, frameCount = 10_000)

        assertTrue(result.report.findings.single().evidence.isEmpty())
        assertTrue(result.rejections.any { it.reason == "frame_not_returned" })
    }

    @Test
    fun communicationEvidenceFrameKeysAreRecorded() {
        val entry = EvidenceLedger().record(
            call = AgentToolCall("call-analysis", "get_communication_analysis"),
            result = successResult(
                "call-analysis",
                "get_communication_analysis",
                data = mapOf(
                    "calls" to listOf(
                        mapOf(
                            "firstFrame" to 1L,
                            "sdpMedia" to listOf(mapOf("offerFrame" to 4L)),
                            "messages" to listOf(mapOf("frameNumber" to 5L)),
                            "callSetupAnalysis" to mapOf(
                                "selectedAttempt" to mapOf(
                                    "finalResponseFrame" to 6L,
                                    "ackFrame" to 7L
                                )
                            )
                        )
                    ),
                    "mediaSessions" to listOf(
                        mapOf(
                            "mLines" to listOf(
                                mapOf(
                                    "offerFrame" to 2L,
                                    "answerFrame" to 3L,
                                    "directions" to listOf(
                                        mapOf(
                                            "firstFrame" to 8L,
                                            "lastFrame" to 9L,
                                            "anomalyFrames" to listOf(10L)
                                        )
                                    ),
                                    "rtcpReports" to listOf(
                                        mapOf("reportFrames" to listOf(11L))
                                    ),
                                    "findings" to listOf(
                                        mapOf("evidenceFrames" to listOf(12L))
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            stepIndex = 1
        )

        assertEquals((1L..12L).toSet(), entry.frameNumbers)
    }

    @Test
    fun frameOutsideTheCaptureIsRemoved() {
        val ledger = ledgerWith(
            call("call-expert", "get_expert_info", data = mapOf("frames" to listOf(900L)))
        )
        val report = reportWith(evidence(sourceToolCallId = "call-expert", frameNumber = 900L))

        val result = validate(report, ledger, frameCount = 100)

        assertTrue(result.report.findings.single().evidence.isEmpty())
        assertTrue(result.rejections.any { it.reason == "frame_out_of_range" })
    }

    @Test
    fun frameActuallyReturnedByTheToolSurvives() {
        val ledger = ledgerWith(
            call(
                "call-expert",
                "get_expert_info",
                data = mapOf("items" to listOf(mapOf("frameNumber" to 7L, "severity" to "error")))
            )
        )
        val report = reportWith(evidence(sourceToolCallId = "call-expert", frameNumber = 7L))

        val result = validate(report, ledger)

        assertEquals(1, result.report.findings.single().evidence.size)
        assertTrue(result.rejections.isEmpty())
    }

    @Test
    fun displayFilterNeverCompiledByTheHostIsRemoved() {
        val ledger = ledgerWith(
            call("call-expert", "get_expert_info", data = mapOf("total" to 3))
        )
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert",
                displayFilter = "tcp.analysis.retransmission"
            )
        )

        val result = validate(report, ledger)

        assertTrue(result.report.findings.single().evidence.isEmpty())
        assertTrue(result.rejections.any { it.reason == "filter_not_validated" })
    }

    @Test
    fun filterReturnedByAToolMayBeCited() {
        val ledger = ledgerWith(
            call(
                "call-expert",
                "get_expert_info",
                data = mapOf(
                    "items" to listOf(
                        mapOf(
                            "frameNumber" to 7L,
                            "displayFilter" to "tcp.analysis.retransmission"
                        )
                    )
                )
            )
        )
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert",
                displayFilter = "tcp.analysis.retransmission"
            )
        )

        val result = validate(report, ledger)

        assertEquals(1, result.report.findings.single().evidence.size)
    }

    @Test
    fun filterRejectedByTheEngineIsNotPromotedToValidated() {
        // validate_display_filter answers valid=false as a *successful* result;
        // the filter it reports on must not become citable because of that.
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-bad", "validate_display_filter", mapOf("filter" to "tcp.portt == 443")),
                result = successResult(
                    "call-bad",
                    "validate_display_filter",
                    mapOf("valid" to false, "normalizedFilter" to "tcp.portt == 443")
                ),
                stepIndex = 1
            )
        }
        val report = reportWith(
            evidence(sourceToolCallId = "call-bad", displayFilter = "tcp.portt == 443")
        )

        val result = validate(report, ledger)

        assertTrue(result.report.findings.single().evidence.isEmpty())
        assertTrue(result.rejections.any { it.reason == "filter_not_validated" })
    }

    @Test
    fun fieldNotProjectedByTheToolIsRemoved() {
        val ledger = ledgerWith(
            call(
                "call-fields",
                "get_packet_fields",
                data = mapOf("fields" to listOf("sip.Method", "sip.Status-Code"))
            )
        )
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-fields",
                type = AgentEvidenceType.Field,
                field = "sip.Invented-Header"
            )
        )

        val result = validate(report, ledger)

        assertTrue(result.report.findings.single().evidence.isEmpty())
        assertTrue(result.rejections.any { it.reason == "field_not_projected" })
    }

    @Test
    fun statisticalEvidenceNeedsAMetricAndAnObservedValue() {
        val ledger = ledgerWith(
            call("call-overview", "get_capture_overview", data = mapOf("protocolHierarchy" to listOf("tcp")))
        )
        val report = reportWith(
            evidence(sourceToolCallId = "call-overview", type = AgentEvidenceType.Statistic)
        )

        val result = validate(report, ledger)

        assertTrue(result.report.findings.single().evidence.isEmpty())
        assertTrue(result.rejections.any { it.reason == "statistic_without_metric" })
    }

    @Test
    fun statisticalEvidenceNamingARealMetricSurvives() {
        val ledger = ledgerWith(
            call("call-overview", "get_capture_overview", data = mapOf("protocolHierarchy" to listOf("tcp")))
        )
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            )
        )

        val result = validate(report, ledger)

        assertEquals(1, result.report.findings.single().evidence.size)
    }

    @Test
    fun fabricatedMetricValueIsRetainedButCapsConfidenceAtLow() {
        val ledger = ledgerWith(
            call(
                "call-statistics",
                "get_statistics",
                data = mapOf("retransmissionCount" to 3)
            )
        )
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-statistics",
                type = AgentEvidenceType.Statistic,
                metric = "retransmissionCount",
                observedValue = "1847"
            ),
            confidence = AgentConfidence.High
        )

        val result = validate(report, ledger)

        assertEquals(1, result.report.findings.single().evidence.size)
        assertEquals(AgentConfidence.Low, result.report.findings.single().confidence)
        assertTrue(result.downgrades.any { it.contains("metric_value_mismatch") })
        assertTrue(result.rejections.isEmpty())
    }

    @Test
    fun containerMetricCannotBeCitedAsAScalar() {
        val ledger = ledgerWith(
            call(
                "call-statistics",
                "get_statistics",
                data = mapOf("retransmissions" to mapOf("count" to 3))
            )
        )
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-statistics",
                type = AgentEvidenceType.Statistic,
                metric = "retransmissions",
                observedValue = "3"
            )
        )

        val result = validate(report, ledger)

        assertTrue(result.report.findings.single().evidence.isEmpty())
        assertTrue(result.rejections.any { it.reason == "metric_not_returned" })
    }

    @Test
    fun acceptedDottedMetricSuffixStillChecksItsObservedValue() {
        val ledger = ledgerWith(
            call(
                "call-statistics",
                "get_statistics",
                data = mapOf(
                    "summary" to mapOf(
                        "tcp" to mapOf("retransmissionCount" to 3)
                    )
                )
            )
        )
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-statistics",
                type = AgentEvidenceType.Statistic,
                metric = "tcp.retransmissionCount",
                observedValue = "1847"
            ),
            confidence = AgentConfidence.High
        )

        val result = validate(report, ledger)

        assertEquals(1, result.report.findings.single().evidence.size)
        assertEquals(AgentConfidence.Low, result.report.findings.single().confidence)
        assertTrue(result.downgrades.any { it.contains("metric_value_mismatch") })
        assertTrue(result.rejections.isEmpty())
    }

    @Test
    fun evidenceFromAFailedToolCallIsRemoved() {
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-timeout", "get_expert_info"),
                result = AgentToolResult(
                    toolCallId = "call-timeout",
                    toolName = "get_expert_info",
                    success = false,
                    error = AgentError(AgentErrorCode.TOOL_TIMEOUT, "timed out", retryable = true)
                ),
                stepIndex = 1
            )
        }
        val report = reportWith(evidence(sourceToolCallId = "call-timeout"))

        val result = validate(report, ledger)

        assertTrue(result.report.findings.single().evidence.isEmpty())
        assertTrue(result.rejections.any { it.reason == "failed_source" })
    }

    // ------------------------------------------------------- negative evidence

    @Test
    fun negativeClaimWithoutScopeIsRejected() {
        val ledger = ledgerWith(
            call("call-expert", "get_expert_info", data = mapOf("total" to 0))
        )
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert",
                observation = "No retransmissions were present in the capture."
            )
        )

        val result = validate(report, ledger)

        assertTrue(result.report.findings.single().evidence.isEmpty())
        assertTrue(result.rejections.any { it.reason == "negative_without_filter" })
    }

    @Test
    fun negativeClaimWithoutTimeRangeIsRejected() {
        val ledger = ledgerWith(
            call(
                "call-expert",
                "get_expert_info",
                data = mapOf("filter" to "tcp.analysis.retransmission", "total" to 0)
            )
        )
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert",
                displayFilter = "tcp.analysis.retransmission",
                observation = "No retransmissions were observed."
            )
        )

        val result = validate(report, ledger)

        assertTrue(result.rejections.any { it.reason == "negative_without_time_range" })
    }

    @Test
    fun negativeClaimFromATruncatedSourceIsRejected() {
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-expert", "get_expert_info", mapOf("filter" to "tcp.flags.reset == 1")),
                result = successResult(
                    "call-expert",
                    "get_expert_info",
                    data = mapOf("total" to 500),
                    returnedCount = 100L,
                    totalCount = 500L,
                    truncated = true
                ),
                stepIndex = 1
            )
        }
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert",
                displayFilter = "tcp.flags.reset == 1",
                observation = "No resets were found.",
                timeRangeStartMillis = 0L,
                timeRangeEndMillis = 60_000L
            )
        )

        val result = validate(report, ledger)

        assertTrue(result.rejections.any { it.reason == "negative_from_incomplete_source" })
    }

    @Test
    fun chineseNegativeClaimStillNeedsATimeRange() {
        val ledger = ledgerWith(
            call(
                "call-expert",
                "get_expert_info",
                arguments = mapOf("filter" to "tcp.analysis.retransmission"),
                data = mapOf("filter" to "tcp.analysis.retransmission", "total" to 0)
            )
        )
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert",
                displayFilter = "tcp.analysis.retransmission",
                observation = "未发现重传"
            )
        )

        val result = validate(report, ledger)

        assertTrue(result.rejections.any { it.reason == "negative_without_time_range" })
    }

    @Test
    fun chineseNegativeClaimWithAnExecutedZeroMatchFilterSurvives() {
        val filter = "tcp.analysis.retransmission"
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-filtered", "get_expert_info"),
                result = AgentToolResult(
                    toolCallId = "call-filtered",
                    toolName = "get_expert_info",
                    success = true,
                    data = mapOf("totalCount" to 0L),
                    returnedCount = 0L,
                    totalCount = 0L,
                    provenance = AgentProvenance(
                        displayFilter = filter,
                        returnedCount = 0L,
                        totalCount = 0L
                    )
                ),
                stepIndex = 1
            )
        }
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-filtered",
                displayFilter = filter,
                observation = "未发现重传",
                timeRangeStartMillis = 0L,
                timeRangeEndMillis = 60_000L
            )
        )

        val result = validate(report, ledger)

        assertEquals(1, result.report.findings.single().evidence.size)
        assertTrue(result.rejections.isEmpty())
    }

    @Test
    fun negativeClaimRequiresTheFilterToHaveBeenExecuted() {
        val filter = "tcp.analysis.retransmission"
        val ledger = ledgerWith(
            call(
                "call-validate",
                "validate_display_filter",
                arguments = mapOf("filter" to filter),
                data = mapOf("valid" to true, "normalizedFilter" to filter)
            )
        )
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-validate",
                displayFilter = filter,
                observation = "No retransmissions were observed.",
                timeRangeStartMillis = 0L,
                timeRangeEndMillis = 60_000L
            )
        )

        val result = validate(report, ledger)

        assertTrue(result.rejections.any { it.reason == "negative_filter_never_executed" })
    }

    @Test
    fun negativeClaimIsRejectedWhenTheExecutedFilterHasMatches() {
        val filter = "tcp.analysis.retransmission"
        val ledger = ledgerWith(
            call(
                "call-expert",
                "get_expert_info",
                arguments = mapOf("filter" to filter),
                data = mapOf("filter" to filter, "total" to 2)
            )
        )
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert",
                displayFilter = filter,
                observation = "No retransmissions were observed.",
                timeRangeStartMillis = 0L,
                timeRangeEndMillis = 60_000L
            )
        )

        val result = validate(report, ledger)

        assertTrue(result.rejections.any { it.reason == "negative_contradicted_by_matches" })
    }

    @Test
    fun protocolPositiveTermsAreNotTreatedAsNegativeClaims() {
        val ledger = ledgerWith(
            call(
                "call-observation",
                "get_expert_info",
                data = mapOf("message" to "TCP zero window; SIP 404 not found")
            )
        )
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-observation",
                type = AgentEvidenceType.Observation,
                observation = "TCP zero window and SIP 404 not found were observed."
            )
        )

        val result = validate(report, ledger)

        assertEquals(1, result.report.findings.single().evidence.size)
        assertTrue(result.rejections.isEmpty())
    }

    @Test
    fun fullyQualifiedNegativeClaimSurvives() {
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-expert", "get_expert_info", mapOf("filter" to "tcp.flags.reset == 1")),
                result = successResult(
                    "call-expert",
                    "get_expert_info",
                    data = mapOf("total" to 0),
                    returnedCount = 0L,
                    totalCount = 0L
                ),
                stepIndex = 1
            )
        }
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert",
                displayFilter = "tcp.flags.reset == 1",
                observation = "No resets were found.",
                timeRangeStartMillis = 0L,
                timeRangeEndMillis = 60_000L
            )
        )

        val result = validate(report, ledger)

        assertEquals(1, result.report.findings.single().evidence.size)
        assertTrue(result.rejections.isEmpty())
    }

    // ----------------------------- OPT-VAL-04-02 polarity-driven negative path

    // [a] The trigger has migrated: with `polarity=Negative` and a grounded
    // absence claim, even a citation whose observation names no marker is
    // reviewed against the filter/time-range/complete/0-matches requirements.
    @Test
    fun negativePolarityFindingScrutinisesEveryCitationOnceGrounded() {
        val filter = "tcp.flags.reset == 1"
        val ledger = zeroMatchScanLedger(filter)
        val anchor = groundedNegativeEvidence(filter)
        val unmarked = evidence(
            sourceToolCallId = "call-reset-scan",
            observation = "The reset inventory was reviewed."
        )

        val result = validate(
            reportWithPolarity(AgentFindingPolarity.Negative, anchor, unmarked),
            ledger
        )

        val rejection = result.rejections.single { it.reason == "negative_without_filter" }
        assertEquals("finding-1", rejection.findingId)
        assertTrue(rejection.detail.contains("a citation of a finding declared Negative"))
        val surviving = result.report.findings.single().evidence
        assertEquals(listOf(anchor), surviving)

        // Contrast: without the declared polarity (Unknown) the same
        // citations keep the legacy per-marker behaviour: nothing to reject.
        val legacy = validate(reportWith(anchor, unmarked), ledger)
        assertTrue(legacy.rejections.isEmpty())
        assertEquals(2, legacy.report.findings.single().evidence.size)
    }

    // [b] A grounded negative finding keeps every citation that meets all
    // four requirements, marker prose or not.
    @Test
    fun groundedNegativeFindingKeepsFullyQualifiedCitations() {
        val filter = "tcp.flags.reset == 1"
        val ledger = zeroMatchScanLedger(filter)
        val anchor = groundedNegativeEvidence(filter)
        val second = groundedNegativeEvidence(
            filter,
            observation = "The zero-match scan supports this claim."
        )

        val result = validate(
            reportWithPolarity(AgentFindingPolarity.Negative, anchor, second),
            ledger
        )

        assertTrue(result.rejections.isEmpty())
        val finding = result.report.findings.single()
        assertEquals(2, finding.evidence.size)
        assertFalse(finding.conclusion.startsWith("Unverified hypothesis:"))
    }

    // [c] §3 degradation contract: a missing polarity field (old report /
    // structured output unavailable) keeps the legacy marker path byte for
    // byte, and a declared-negative claim without a grounded citation keeps
    // at least the same marker-level rejections it had before the migration.
    @Test
    fun undeclaredPolarityKeepsTheLegacyMarkerPathVerbatim() {
        val ledger = ledgerWith(
            call("call-expert", "get_expert_info", data = mapOf("total" to 0))
        )
        val markerEvidence = evidence(
            sourceToolCallId = "call-expert",
            observation = "No retransmissions were present in the capture."
        )

        val unknown = validate(
            reportWithPolarity(AgentFindingPolarity.Unknown, markerEvidence),
            ledger
        )
        val rejection = unknown.rejections.single { it.reason == "negative_without_filter" }
        assertEquals(
            "a negative statement did not say which display filter was searched",
            rejection.detail
        )

        val ungrounded = validate(
            reportWithPolarity(AgentFindingPolarity.Negative, markerEvidence),
            ledger
        )
        assertTrue(ungrounded.rejections.any { it.reason == "negative_without_filter" })
    }

    // [d] (OPT-VAL-04-03 reversal of the 04-02 placeholder) Positive/Neutral
    // declarations were, as of 04-02, left untouched by marker text on the way
    // to the full double track. With the cross-check now live, a citation that
    // claims an absence under a presence declaration contradicts the finding's
    // own polarity and is rejected as `polarity_claim_conflict`.
    @Test
    fun declaredPositiveAndNeutralMarkerContradictionIsRejected() {
        val ledger = ledgerWith(
            call("call-expert", "get_expert_info", data = mapOf("total" to 2))
        )
        val markerEvidence = evidence(
            sourceToolCallId = "call-expert",
            observation = "No retransmissions were observed."
        )

        for (polarity in listOf(AgentFindingPolarity.Positive, AgentFindingPolarity.Neutral)) {
            val result = validate(reportWithPolarity(polarity, markerEvidence), ledger)
            val rejection = result.rejections.single { it.reason == "polarity_claim_conflict" }
            assertEquals("finding-1", rejection.findingId)
            assertEquals(
                "declared $polarity loses the contradicting citation",
                0,
                result.report.findings.single().evidence.size
            )
        }

        // Contrast (unchanged): the same citation on an undeclared report is
        // rejected by the legacy marker path, never as a conflict.
        val legacy = validate(reportWith(markerEvidence), ledger)
        assertTrue(legacy.rejections.any { it.reason == "negative_without_filter" })
        assertTrue(legacy.rejections.none { it.reason == "polarity_claim_conflict" })
    }

    // [a] A `polarity_claim_conflict` rejection travels the ordinary rejection
    // channel, so it reaches limitations and carries only a stable id and the
    // declared polarity — never the model's observation prose.
    @Test
    fun positivePolarityConflictRejectionFlowsIntoLimitations() {
        val ledger = ledgerWith(
            call("call-expert", "get_expert_info", data = mapOf("total" to 2))
        )
        val observation = "No retransmissions were observed."
        val result = validate(
            reportWithPolarity(
                AgentFindingPolarity.Positive,
                evidence(sourceToolCallId = "call-expert", observation = observation)
            ),
            ledger
        )

        val rejection = result.rejections.single { it.reason == "polarity_claim_conflict" }
        assertTrue(rejection.detail.contains("call-expert"))
        assertTrue(rejection.detail.contains("declared positive"))
        assertFalse(
            "the detail must not quote the observation",
            rejection.detail.contains(observation)
        )
        // The rejection surfaces as a limitation on the surviving report.
        assertTrue(
            result.report.limitations.any { it.contains("contradicting that declaration") }
        )
    }

    // [b] Neutral declaration is held to the same standard as Positive.
    @Test
    fun neutralPolarityConflictRejectionRemovesEvidence() {
        val ledger = ledgerWith(
            call("call-expert", "get_expert_info", data = mapOf("total" to 2))
        )
        val result = validate(
            reportWithPolarity(
                AgentFindingPolarity.Neutral,
                evidence(sourceToolCallId = "call-expert", observation = "No anomalies were found.")
            ),
            ledger
        )
        assertEquals("polarity_claim_conflict", result.rejections.single().reason)
        assertTrue(result.report.findings.single().evidence.isEmpty())
    }

    // [c] With the migration switch off, a Positive declaration that meets a
    // marker falls back to the legacy per-observation trigger (the four
    // requirements), never a conflict rejection.
    @Test
    fun switchOffPositiveMarkerUsesLegacyTriggerNotConflict() {
        val legacyPolicy = AgentPolicy(findingPolarityNegativeValidation = false)
        val ledger = ledgerWith(
            call("call-expert", "get_expert_info", data = mapOf("total" to 2))
        )
        val report = reportWithPolarity(
            AgentFindingPolarity.Positive,
            evidence(sourceToolCallId = "call-expert", observation = "No retransmissions were observed.")
        )

        val result = validateWithPolicy(report, ledger, legacyPolicy)
        assertTrue(result.rejections.none { it.reason == "polarity_claim_conflict" })
        assertTrue(result.rejections.any { it.reason == "negative_without_filter" })
    }

    // [d] The §3 degradation contract: an undeclared polarity (old report /
    // structured output unavailable) never raises a conflict, whatever the
    // observation says.
    @Test
    fun unknownPolarityNeverProducesPolarityConflict() {
        val ledger = ledgerWith(
            call("call-expert", "get_expert_info", data = mapOf("total" to 2))
        )
        val result = validate(
            reportWithPolarity(
                AgentFindingPolarity.Unknown,
                evidence(sourceToolCallId = "call-expert", observation = "No retransmissions were observed.")
            ),
            ledger
        )
        assertTrue(result.rejections.none { it.reason == "polarity_claim_conflict" })
        assertTrue(result.rejections.any { it.reason == "negative_without_filter" })
    }

    // [e] The reverse half of the double track, pinned: a declared-Negative
    // finding whose citation carries none of the legacy markers but satisfies
    // all four negative requirements survives — the absence of marker prose is
    // never itself a reason to reject.
    @Test
    fun declaredNegativeWithoutMarkerSurvivesWhenRequirementsMet() {
        val filter = "tcp.flags.reset == 1"
        val ledger = zeroMatchScanLedger(filter)
        val unmarkedButQualified = groundedNegativeEvidence(
            filter,
            observation = "The reset inventory scan completed."
        )

        val result = validate(
            reportWithPolarity(AgentFindingPolarity.Negative, unmarkedButQualified),
            ledger
        )

        assertTrue(result.rejections.isEmpty())
        assertEquals(1, result.report.findings.single().evidence.size)
    }

    // [e] The rollback switch: off restores the pre-migration behaviour for
    // both migrated directions — [a]'s extra rejections disappear, [d]'s
    // marker trigger comes back regardless of the declared polarity.
    @Test
    fun switchingThePolarityGateOffRestoresTheLegacyMarkerTrigger() {
        val legacyPolicy = AgentPolicy(findingPolarityNegativeValidation = false)
        val filter = "tcp.flags.reset == 1"
        val scanLedger = zeroMatchScanLedger(filter)
        val groundedReport = reportWithPolarity(
            AgentFindingPolarity.Negative,
            groundedNegativeEvidence(filter),
            evidence(
                sourceToolCallId = "call-reset-scan",
                observation = "The reset inventory was reviewed."
            )
        )

        val offA = validateWithPolicy(groundedReport, scanLedger, legacyPolicy)
        assertTrue(offA.rejections.isEmpty())
        assertEquals(2, offA.report.findings.single().evidence.size)

        val conflictLedger = ledgerWith(
            call("call-expert", "get_expert_info", data = mapOf("total" to 2))
        )
        val positiveReport = reportWithPolarity(
            AgentFindingPolarity.Positive,
            evidence(
                sourceToolCallId = "call-expert",
                observation = "No retransmissions were observed."
            )
        )

        val offD = validateWithPolicy(positiveReport, conflictLedger, legacyPolicy)
        assertTrue(offD.rejections.any { it.reason == "negative_without_filter" })
    }

    // [f] The time-range requirement is still read from the evidence's own
    // structured fields: with a grounded negative claim, the same citation
    // survives only once both endpoints are present on the evidence.
    @Test
    fun negativeScrutinyStillReadsTimeRangeFromTheEvidenceFields() {
        val filter = "tcp.flags.reset == 1"
        val ledger = zeroMatchScanLedger(filter)
        val anchor = groundedNegativeEvidence(filter)
        val missingRange = evidence(
            sourceToolCallId = "call-reset-scan",
            displayFilter = filter,
            observation = "The scan covered the requested range."
        )

        val withoutRange = validate(
            reportWithPolarity(AgentFindingPolarity.Negative, anchor, missingRange),
            ledger
        )
        assertTrue(withoutRange.rejections.any { it.reason == "negative_without_time_range" })
        assertEquals(1, withoutRange.report.findings.single().evidence.size)

        val withRange = missingRange.copy(
            timeRangeStartMillis = 0L,
            timeRangeEndMillis = 60_000L
        )
        val complete = validate(
            reportWithPolarity(AgentFindingPolarity.Negative, anchor, withRange),
            ledger
        )
        assertTrue(complete.rejections.isEmpty())
        assertEquals(2, complete.report.findings.single().evidence.size)
    }

    // The complete-source and 0-matches requirements keep their existing
    // ledger material under finding-level scrutiny too: a truncated scan and
    // an executed filter with matches are both rejected for citations that
    // never wrote absence prose.
    @Test
    fun findingLevelScrutinyKeepsCompletenessAndZeroMatchRequirements() {
        val filter = "tcp.flags.reset == 1"
        val truncatedFilter = "tcp.flags.syn == 0 && tcp.flags.ack == 0"
        val retransmissionFilter = "tcp.analysis.retransmission"
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-reset-scan", "get_expert_info", mapOf("filter" to filter)),
                result = successResult(
                    "call-reset-scan",
                    "get_expert_info",
                    mapOf("filter" to filter, "totalCount" to 0L),
                    returnedCount = 0L,
                    totalCount = 0L
                ),
                stepIndex = 1
            )
            record(
                call = AgentToolCall(
                    "call-trunc-scan",
                    "get_expert_info",
                    mapOf("filter" to truncatedFilter)
                ),
                result = successResult(
                    "call-trunc-scan",
                    "get_expert_info",
                    mapOf("filter" to truncatedFilter, "totalCount" to 500L),
                    returnedCount = 100L,
                    totalCount = 500L,
                    truncated = true
                ),
                stepIndex = 2
            )
            record(
                call = AgentToolCall(
                    "call-retrans",
                    "get_expert_info",
                    mapOf("filter" to retransmissionFilter)
                ),
                result = successResult(
                    "call-retrans",
                    "get_expert_info",
                    mapOf("filter" to retransmissionFilter, "total" to 2L),
                    returnedCount = 2L,
                    totalCount = 2L
                ),
                stepIndex = 3
            )
        }
        val anchor = groundedNegativeEvidence(filter)

        val incomplete = evidence(
            sourceToolCallId = "call-trunc-scan",
            displayFilter = truncatedFilter,
            observation = "The SYN-only inventory was reviewed.",
            timeRangeStartMillis = 0L,
            timeRangeEndMillis = 60_000L
        )
        val incompleteResult = validate(
            reportWithPolarity(AgentFindingPolarity.Negative, anchor, incomplete),
            ledger
        )
        assertTrue(
            incompleteResult.rejections.any { it.reason == "negative_from_incomplete_source" }
        )

        val contradicted = evidence(
            sourceToolCallId = "call-retrans",
            displayFilter = retransmissionFilter,
            observation = "The retransmission inventory was reviewed.",
            timeRangeStartMillis = 0L,
            timeRangeEndMillis = 60_000L
        )
        val contradictedResult = validate(
            reportWithPolarity(AgentFindingPolarity.Negative, anchor, contradicted),
            ledger
        )
        assertTrue(
            contradictedResult.rejections.any { it.reason == "negative_contradicted_by_matches" }
        )
    }

    private fun reportWithPolarity(
        polarity: AgentFindingPolarity,
        vararg evidenceItems: AgentEvidence,
        confidence: AgentConfidence = AgentConfidence.Medium
    ) = reportWith(*evidenceItems, confidence = confidence).let { report ->
        report.copy(findings = report.findings.map { it.copy(polarity = polarity) })
    }

    /** A successful, complete expert-info scan whose filter matched nothing. */
    private fun zeroMatchScanLedger(filter: String) = EvidenceLedger().apply {
        record(
            call = AgentToolCall("call-reset-scan", "get_expert_info", mapOf("filter" to filter)),
            result = successResult(
                "call-reset-scan",
                "get_expert_info",
                mapOf("filter" to filter, "totalCount" to 0L),
                returnedCount = 0L,
                totalCount = 0L
            ),
            stepIndex = 1
        )
    }

    /** A citation that satisfies all four negative requirements by itself. */
    private fun groundedNegativeEvidence(
        filter: String,
        observation: String = "No resets were found."
    ) = evidence(
        sourceToolCallId = "call-reset-scan",
        displayFilter = filter,
        observation = observation,
        timeRangeStartMillis = 0L,
        timeRangeEndMillis = 60_000L
    )

    // ------------------------------------------------------------- confidence

    @Test
    fun highConfidenceIsCappedWhenOnlyOneEvidenceTypeSurvives() {
        val ledger = ledgerWith(
            call(
                "call-expert",
                "get_expert_info",
                data = mapOf("items" to listOf(mapOf("frameNumber" to 7L)))
            )
        )
        val report = reportWith(
            evidence(sourceToolCallId = "call-expert", frameNumber = 7L),
            confidence = AgentConfidence.High
        )

        val result = validate(report, ledger)

        assertEquals(AgentConfidence.Medium, result.report.findings.single().confidence)
        assertTrue(result.downgrades.any { it.contains("Medium") })
    }

    @Test
    fun highConfidenceSurvivesTwoIndependentEvidenceTypes() {
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-overview", "get_capture_overview"),
                result = successResult(
                    "call-overview",
                    "get_capture_overview",
                    mapOf("protocolHierarchy" to listOf("tcp"))
                ),
                stepIndex = 1
            )
            record(
                call = AgentToolCall("call-expert", "get_expert_info"),
                result = successResult(
                    "call-expert",
                    "get_expert_info",
                    mapOf("items" to listOf(mapOf("frameNumber" to 7L)))
                ),
                stepIndex = 2
            )
        }
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            evidence(
                sourceToolCallId = "call-expert",
                type = AgentEvidenceType.ExpertInfo,
                frameNumber = 7L
            ),
            confidence = AgentConfidence.High
        )

        val result = validate(report, ledger)

        assertEquals(AgentConfidence.High, result.report.findings.single().confidence)
    }

    @Test
    fun truncatedSourceCostsOneConfidenceLevel() {
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-overview", "get_capture_overview"),
                result = successResult(
                    "call-overview",
                    "get_capture_overview",
                    mapOf("protocolHierarchy" to listOf("tcp")),
                    returnedCount = 20L,
                    totalCount = 400L,
                    truncated = true
                ),
                stepIndex = 1
            )
            record(
                call = AgentToolCall("call-expert", "get_expert_info"),
                result = successResult(
                    "call-expert",
                    "get_expert_info",
                    mapOf("items" to listOf(mapOf("frameNumber" to 7L)))
                ),
                stepIndex = 2
            )
        }
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            evidence(
                sourceToolCallId = "call-expert",
                type = AgentEvidenceType.ExpertInfo,
                frameNumber = 7L
            ),
            confidence = AgentConfidence.High
        )

        val result = validate(report, ledger)

        assertEquals(AgentConfidence.Medium, result.report.findings.single().confidence)
    }

    @Test
    fun findingWithNoEvidenceIsCappedAtLow() {
        val report = reportWith(confidence = AgentConfidence.High)

        val result = validate(report, EvidenceLedger())

        assertEquals(AgentConfidence.Low, result.report.findings.single().confidence)
    }

    @Test
    fun infoFindingWithNoEvidenceBecomesAHypothesis() {
        val result = validate(
            reportWith(
                severity = AgentFindingSeverity.Info,
                confidence = AgentConfidence.High,
                conclusion = "The capture is healthy."
            ),
            EvidenceLedger()
        )

        val finding = result.report.findings.single()
        assertEquals(AgentFindingSeverity.Notice, finding.severity)
        assertTrue(finding.conclusion.startsWith("Unverified hypothesis:"))
        assertEquals(AgentConfidence.Low, finding.confidence)
    }

    @Test
    fun modelCannotRaiseConfidenceAboveWhatEvidenceSupports() {
        // The model claims Low; the host never promotes it, even though two
        // independent evidence types would have allowed High.
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-overview", "get_capture_overview"),
                result = successResult(
                    "call-overview",
                    "get_capture_overview",
                    mapOf("protocolHierarchy" to listOf("tcp"))
                ),
                stepIndex = 1
            )
            record(
                call = AgentToolCall("call-expert", "get_expert_info"),
                result = successResult(
                    "call-expert",
                    "get_expert_info",
                    mapOf("items" to listOf(mapOf("frameNumber" to 7L)))
                ),
                stepIndex = 2
            )
        }
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            evidence(
                sourceToolCallId = "call-expert",
                type = AgentEvidenceType.ExpertInfo,
                frameNumber = 7L
            ),
            confidence = AgentConfidence.Low
        )

        val result = validate(report, ledger)

        assertEquals(AgentConfidence.Low, result.report.findings.single().confidence)
    }

    @Test
    fun unevidencedErrorFindingBecomesAHypothesis() {
        val report = reportWith(
            severity = AgentFindingSeverity.Error,
            confidence = AgentConfidence.High,
            conclusion = "The server rejected every registration attempt."
        )

        val result = validate(report, EvidenceLedger())

        val finding = result.report.findings.single()
        assertEquals(AgentFindingSeverity.Notice, finding.severity)
        assertTrue(finding.conclusion.startsWith("Unverified hypothesis:"))
        assertEquals(AgentConfidence.Low, finding.confidence)
    }

    // ----------------------------------------------------------- completeness

    @Test
    fun modelCannotDeclareCompleteAfterHittingTheStepLimit() {
        val ledger = ledgerWith(call("call-overview", "get_capture_overview", data = mapOf("ok" to true)))
        val report = reportWith().copy(completeness = AgentReportCompleteness.Complete)

        val result = validate(report, ledger, stopReason = AgentStopReason.MaxStepsReached)

        assertEquals(AgentReportCompleteness.Incomplete, result.report.completeness)
        assertTrue(result.report.limitations.any { it.contains("step limit") })
    }

    @Test
    fun truncatedToolResultDoesNotCapCompletenessWhenTheModelFinishes() {
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-expert", "get_expert_info"),
                result = successResult(
                    "call-expert",
                    "get_expert_info",
                    mapOf("items" to emptyList<Any>()),
                    returnedCount = 50L,
                    totalCount = 900L,
                    truncated = true
                ),
                stepIndex = 1
            )
        }
        val report = reportWith().copy(completeness = AgentReportCompleteness.Complete)

        val result = validate(report, ledger)

        // The model ended the run with its own final report, so a truncated read
        // no longer caps the verdict below Complete.  The shortfall is still
        // named in the limitations: 850 unexamined entries and 1 are both
        // "truncated", and a reader has to be able to tell them apart.
        assertEquals(AgentReportCompleteness.Complete, result.report.completeness)
        assertTrue(
            result.report.limitations.any {
                it.contains("get_expert_info") && it.contains("50 of 900") && it.contains("850")
            }
        )
    }

    @Test
    fun toolFailureCapsCompletenessAtPartial() {
        val ledger = ledgerWith(
            call("call-expert", "get_expert_info", data = mapOf("ok" to true))
        )
        val report = reportWith().copy(completeness = AgentReportCompleteness.Complete)

        val result = validate(report, ledger, stopReason = AgentStopReason.ToolFailure)

        assertEquals(AgentReportCompleteness.Partial, result.report.completeness)
    }

    @Test
    fun cancelledRunIsAlwaysIncomplete() {
        val report = reportWith().copy(completeness = AgentReportCompleteness.Complete)

        val result = validate(report, EvidenceLedger(), stopReason = AgentStopReason.Cancelled)

        assertEquals(AgentReportCompleteness.Incomplete, result.report.completeness)
    }

    @Test
    fun cleanRunWithEvidenceIsComplete() {
        val ledger = ledgerWith(
            call(
                "call-expert",
                "get_expert_info",
                data = mapOf("items" to listOf(mapOf("frameNumber" to 7L)))
            )
        )
        val report = reportWith(evidence(sourceToolCallId = "call-expert", frameNumber = 7L))

        val result = validate(report, ledger)

        assertEquals(AgentReportCompleteness.Complete, result.report.completeness)
    }

    @Test
    fun provenanceIsRewrittenFromTheRunNotTheModel() {
        val ledger = ledgerWith(call("call-overview", "get_capture_overview", data = mapOf("ok" to true)))
        val report = reportWith().copy(
            provenance = com.example.layanalyzer.model.AgentReportProvenance(
                captureFingerprint = "attacker-supplied",
                displayFilter = "attacker-filter",
                toolCallIds = listOf("call-that-never-ran")
            )
        )

        val result = validate(report, ledger)

        assertEquals("sha-test", result.report.provenance.captureFingerprint)
        assertEquals(listOf("call-overview"), result.report.provenance.toolCallIds)
        assertFalse(result.report.provenance.displayFilter == "attacker-filter")
    }

    // ------------------------------------------- OPT-VAL-07 precise truncation

    @Test
    fun citationConfinedToTruncatedSubsetKeepsConfidenceAndAddsLimitation() {
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-expert", "get_expert_info"),
                result = successResult(
                    "call-expert",
                    "get_expert_info",
                    mapOf("items" to listOf(mapOf("frameNumber" to 7L))),
                    returnedCount = 100L,
                    totalCount = 500L,
                    truncated = true
                ),
                stepIndex = 1
            )
            record(
                call = AgentToolCall("call-overview", "get_capture_overview"),
                result = successResult(
                    "call-overview",
                    "get_capture_overview",
                    mapOf("protocolHierarchy" to listOf("tcp"))
                ),
                stepIndex = 2
            )
        }
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert",
                type = AgentEvidenceType.ExpertInfo,
                frameNumber = 7L
            ),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High
        )

        val result = validateWithPolicy(report, ledger, AgentPolicy(preciseTruncationDowngrade = true))

        // The truncated citation names a frame the call really returned, so the
        // truncation cannot undercut this conclusion: it keeps High.
        assertEquals(AgentConfidence.High, result.report.findings.single().confidence)
        assertTrue(result.downgrades.none { it.contains("Lowered confidence") })
        assertTrue(
            result.report.limitations.any {
                it.contains("cites only data") && it.contains("call-expert")
            }
        )
    }

    @Test
    fun framelessStatisticFromTruncatedSourceStillDowngrades() {
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-expert", "get_expert_info"),
                result = successResult(
                    "call-expert",
                    "get_expert_info",
                    mapOf("retransmissionCount" to 3),
                    returnedCount = 100L,
                    totalCount = 500L,
                    truncated = true
                ),
                stepIndex = 1
            )
            record(
                call = AgentToolCall("call-overview", "get_capture_overview"),
                result = successResult(
                    "call-overview",
                    "get_capture_overview",
                    mapOf("items" to listOf(mapOf("frameNumber" to 5L)))
                ),
                stepIndex = 2
            )
        }
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert",
                type = AgentEvidenceType.Statistic,
                metric = "retransmissionCount",
                observedValue = "3"
            ),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.ExpertInfo,
                frameNumber = 5L
            ),
            confidence = AgentConfidence.High
        )

        val result = validateWithPolicy(report, ledger, AgentPolicy(preciseTruncationDowngrade = true))

        // A statistic that names no frame speaks for the whole read, including
        // the unseen tail, so the cap stands and no exemption is recorded.
        assertEquals(AgentConfidence.Medium, result.report.findings.single().confidence)
        assertTrue(result.report.limitations.none { it.contains("cites only data") })
    }

    @Test
    fun aggregateAssertionDowngradesEvenWhenCitationIsConfined() {
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-expert", "get_expert_info"),
                result = successResult(
                    "call-expert",
                    "get_expert_info",
                    mapOf("items" to listOf(mapOf("frameNumber" to 7L))),
                    returnedCount = 100L,
                    totalCount = 500L,
                    truncated = true
                ),
                stepIndex = 1
            )
            record(
                call = AgentToolCall("call-overview", "get_capture_overview"),
                result = successResult(
                    "call-overview",
                    "get_capture_overview",
                    mapOf("protocolHierarchy" to listOf("tcp"))
                ),
                stepIndex = 2
            )
        }
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert",
                type = AgentEvidenceType.ExpertInfo,
                frameNumber = 7L
            ),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High,
            conclusion = "Retransmissions account for 12% of all frames."
        )

        val result = validateWithPolicy(report, ledger, AgentPolicy(preciseTruncationDowngrade = true))

        // The conclusion generalises over the whole capture, which a truncated
        // read never saw, so the confinement exemption does not apply.
        assertEquals(AgentConfidence.Medium, result.report.findings.single().confidence)
        assertTrue(result.report.limitations.none { it.contains("cites only data") })
    }

    @Test
    fun runIncompleteStillCapsEvenWhenTruncationIsExempted() {
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-expert", "get_expert_info"),
                result = successResult(
                    "call-expert",
                    "get_expert_info",
                    mapOf("items" to listOf(mapOf("frameNumber" to 7L))),
                    returnedCount = 100L,
                    totalCount = 500L,
                    truncated = true
                ),
                stepIndex = 1
            )
            record(
                call = AgentToolCall("call-overview", "get_capture_overview"),
                result = successResult(
                    "call-overview",
                    "get_capture_overview",
                    mapOf("protocolHierarchy" to listOf("tcp"))
                ),
                stepIndex = 2
            )
        }
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert",
                type = AgentEvidenceType.ExpertInfo,
                frameNumber = 7L
            ),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High
        )

        val result = validateWithPolicy(
            report,
            ledger,
            AgentPolicy(preciseTruncationDowngrade = true),
            stopReason = AgentStopReason.MaxStepsReached
        )

        // Truncation is exempt for this finding, but the run stopping early is a
        // global uncertainty that still costs a level.
        assertEquals(AgentConfidence.Medium, result.report.findings.single().confidence)
    }

    @Test
    fun preciseSwitchOffRestoresBlanketTruncationDowngrade() {
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-expert", "get_expert_info"),
                result = successResult(
                    "call-expert",
                    "get_expert_info",
                    mapOf("items" to listOf(mapOf("frameNumber" to 7L))),
                    returnedCount = 100L,
                    totalCount = 500L,
                    truncated = true
                ),
                stepIndex = 1
            )
            record(
                call = AgentToolCall("call-overview", "get_capture_overview"),
                result = successResult(
                    "call-overview",
                    "get_capture_overview",
                    mapOf("protocolHierarchy" to listOf("tcp"))
                ),
                stepIndex = 2
            )
        }
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert",
                type = AgentEvidenceType.ExpertInfo,
                frameNumber = 7L
            ),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High
        )

        val result = validateWithPolicy(report, ledger, AgentPolicy(preciseTruncationDowngrade = false))

        // The rollback switch restores "any cited truncated source caps a level".
        assertEquals(AgentConfidence.Medium, result.report.findings.single().confidence)
        assertTrue(result.report.limitations.none { it.contains("cites only data") })
    }

    // ------------------------------------ OPT-VAL-07-02 precise truncation matrix
    //
    // Complements the five OPT-VAL-07-01 tests above: those pin the five primary
    // paths (confined exemption, frameless statistic, aggregate, runIncomplete,
    // switch-off).  The cases below widen each dimension by one structural axis
    // (multi-source, rejections inside the surviving set, polarity field,
    // negative text on a complete sibling, multi-finding traces, the
    // zero-tolerance high-confidence mirror) instead of re-asserting the same
    // combination.

    private val preciseTruncationPolicy = AgentPolicy(preciseTruncationDowngrade = true)
    private val legacyTruncationPolicy = AgentPolicy(preciseTruncationDowngrade = false)

    // [matrix 1 + 5] All citations confined, but spread over *two* truncated
    // sources plus one complete fallback: each truncated source must earn its
    // own exemption line (distinctBy toolCallId) and the cap must not apply.
    @Test
    fun citationsConfinedToTwoTruncatedSourcesEachEarnOneExemptionLine() {
        val ledger = ledgerWith(
            truncatedExpertCall(),
            truncatedSummariesCall(),
            completeOverviewCall()
        )
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert-trunc",
                type = AgentEvidenceType.ExpertInfo,
                frameNumber = 7L
            ),
            evidence(
                sourceToolCallId = "call-summaries-trunc",
                type = AgentEvidenceType.Field,
                frameNumber = 12L,
                field = "ip.src"
            ),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High
        )

        val result = validateMatrix(report, ledger, preciseTruncationPolicy)

        val finding = result.report.findings.single()
        assertEquals(3, finding.evidence.size)
        assertEquals(AgentConfidence.High, finding.confidence)
        assertTrue(loweredConfidenceLines(result).isEmpty())
        val exemptions = truncationExemptionLines(result)
        assertEquals(2, exemptions.size)
        // Stable ids only: call id, returned/total counts, and the per-tool unit.
        assertTrue(
            exemptions.any {
                it.contains("call-expert-trunc") && it.contains("100 of 500") && it.contains("entries")
            }
        )
        assertTrue(
            exemptions.any {
                it.contains("call-summaries-trunc") && it.contains("20 of 80") && it.contains("frames")
            }
        )
    }

    // [matrix 2] Inside one finding: one frame inside the returned subset, one
    // frame outside it (removed by decisionFor, so the judgement must be made on
    // the *surviving* set), and a frameless metric from the same truncated call
    // mixed with a complete-source citation.  The frameless survivor keeps the cap.
    @Test
    fun rejectedOutsideSubsetCitationDoesNotHideFramelessSiblingOfTruncatedSource() {
        val ledger = ledgerWith(
            truncatedExpertCall(extraData = mapOf("retransmissionCount" to 3)),
            completeOverviewCall()
        )
        val report = reportWith(
            evidence(sourceToolCallId = "call-expert-trunc", frameNumber = 7L),
            evidence(sourceToolCallId = "call-expert-trunc", frameNumber = 424L),
            evidence(
                sourceToolCallId = "call-expert-trunc",
                type = AgentEvidenceType.Statistic,
                metric = "retransmissionCount",
                observedValue = "3"
            ),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High
        )

        val result = validateMatrix(report, ledger, preciseTruncationPolicy)

        val finding = result.report.findings.single()
        assertTrue(result.rejections.any { it.reason == "frame_not_returned" })
        // The fabricated citation is gone, three survive; the survivor set still
        // contains a frameless citation into the truncated source, so no exemption.
        assertEquals(3, finding.evidence.size)
        assertEquals(AgentConfidence.Medium, finding.confidence)
        assertTrue(truncationExemptionLines(result).isEmpty())
        assertTrue(loweredConfidenceLines(result).any { it.contains("finding-1") })
    }

    // [matrix 3] Negative asserted through the structured polarity field rather
    // than prose: a "nothing is wrong" conclusion must never ride the exemption
    // even when every citation is confined to the returned subset.
    @Test
    fun negativePolarityFindingCannotUseTheConfinementExemption() {
        val ledger = ledgerWith(truncatedExpertCall(), completeOverviewCall())
        val base = reportWith(
            evidence(sourceToolCallId = "call-expert-trunc", frameNumber = 7L),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High
        )
        val report = base.copy(
            findings = base.findings.map {
                it.copy(polarity = AgentFindingPolarity.Negative)
            }
        )

        val result = validateMatrix(report, ledger, preciseTruncationPolicy)

        assertEquals(AgentConfidence.Medium, result.report.findings.single().confidence)
        assertTrue(truncationExemptionLines(result).isEmpty())
    }

    // [matrix 3] A fully-qualified negative citation from a *complete* source
    // survives citation-level checks, but its presence makes the finding an
    // absence claim, which blocks the exemption of its truncated sibling.
    @Test
    fun survivingNegativeClaimOnCompleteSourceCapsExemptedTruncatedSibling() {
        val filter = "tcp.flags.reset == 1"
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-expert-trunc", "get_expert_info"),
                result = successResult(
                    "call-expert-trunc",
                    "get_expert_info",
                    mapOf("items" to listOf(mapOf("frameNumber" to 7L))),
                    returnedCount = 100L,
                    totalCount = 500L,
                    truncated = true
                ),
                stepIndex = 1
            )
            record(
                call = AgentToolCall("call-overview", "get_capture_overview"),
                result = successResult(
                    "call-overview",
                    "get_capture_overview",
                    mapOf("protocolHierarchy" to listOf("tcp"))
                ),
                stepIndex = 2
            )
            record(
                call = AgentToolCall("call-reset-scan", "get_expert_info", mapOf("filter" to filter)),
                result = AgentToolResult(
                    toolCallId = "call-reset-scan",
                    toolName = "get_expert_info",
                    success = true,
                    data = mapOf("filter" to filter, "totalCount" to 0L),
                    returnedCount = 0L,
                    totalCount = 0L,
                    provenance = AgentProvenance(
                        displayFilter = filter,
                        returnedCount = 0L,
                        totalCount = 0L
                    )
                ),
                stepIndex = 3
            )
        }
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-reset-scan",
                displayFilter = filter,
                observation = "No resets were found.",
                timeRangeStartMillis = 0L,
                timeRangeEndMillis = 60_000L
            ),
            evidence(sourceToolCallId = "call-expert-trunc", frameNumber = 7L),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High
        )

        val result = validateMatrix(report, ledger, preciseTruncationPolicy)

        val finding = result.report.findings.single()
        assertTrue(result.rejections.isEmpty())
        assertEquals(3, finding.evidence.size)
        // Three types/sources incl. a complete fallback would top out at High;
        // the absence claim in citation 1 keeps the truncation cap.
        assertEquals(AgentConfidence.Medium, finding.confidence)
        assertTrue(truncationExemptionLines(result).isEmpty())
    }

    // [matrix 3, channel pin] negative_from_incomplete_source is a citation-level
    // rejection and runs *before* any exemption logic: even a frame anchored
    // inside the returned subset cannot rescue an absence claim from a
    // truncated scan.
    @Test
    fun negativeClaimFromTruncatedSourceIsRejectedEvenWithConfinedFrame() {
        val filter = "tcp.flags.reset == 1"
        val ledger = EvidenceLedger().apply {
            record(
                call = AgentToolCall("call-expert-trunc", "get_expert_info", mapOf("filter" to filter)),
                result = AgentToolResult(
                    toolCallId = "call-expert-trunc",
                    toolName = "get_expert_info",
                    success = true,
                    data = mapOf(
                        "items" to listOf(mapOf("frameNumber" to 7L)),
                        "filter" to filter
                    ),
                    truncated = true,
                    returnedCount = 100L,
                    totalCount = 500L,
                    provenance = AgentProvenance(
                        displayFilter = filter,
                        returnedCount = 100L,
                        totalCount = 500L,
                        truncated = true
                    )
                ),
                stepIndex = 1
            )
        }
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert-trunc",
                frameNumber = 7L,
                displayFilter = filter,
                observation = "No resets were found.",
                timeRangeStartMillis = 0L,
                timeRangeEndMillis = 60_000L
            )
        )

        val result = validateMatrix(report, ledger, preciseTruncationPolicy)

        assertTrue(result.rejections.any { it.reason == "negative_from_incomplete_source" })
        assertTrue(result.report.findings.single().evidence.isEmpty())
        assertTrue(truncationExemptionLines(result).isEmpty())
    }

    // [matrix 4] Aggregate asserted in Chinese inside an evidence observation
    // (the 07-01 test put the English marker in the conclusion): a truncated
    // read cannot establish a 所有/占比 claim even when the citation is confined.
    @Test
    fun chineseAggregateMarkersInEvidenceObservationBlockExemption() {
        val ledger = ledgerWith(truncatedExpertCall(), completeOverviewCall())
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert-trunc",
                frameNumber = 7L,
                observation = "重传占所有帧的比例很低，问题集中在媒体流。"
            ),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High
        )

        val result = validateMatrix(report, ledger, preciseTruncationPolicy)

        val finding = result.report.findings.single()
        // The citation survives; only the confidence is capped.
        assertEquals(2, finding.evidence.size)
        assertEquals(AgentConfidence.Medium, finding.confidence)
        assertTrue(truncationExemptionLines(result).isEmpty())
    }

    // [matrix 4, contrast] POSITIVE_EXCEPTIONS reuse: protocol phrases that
    // contain absence words ("zero window", "404 not found") must not trip the
    // negative/aggregate gate, so a confined citation still earns its exemption.
    @Test
    fun protocolExceptionPhrasesDoNotTripTheNegativeOrAggregateGate() {
        val ledger = ledgerWith(truncatedExpertCall(), completeOverviewCall())
        val report = reportWith(
            evidence(
                sourceToolCallId = "call-expert-trunc",
                frameNumber = 7L,
                observation = "Frame 7 carried a TCP zero window notification " +
                    "and a SIP 404 not found response."
            ),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High,
            conclusion = "The peer advertised flow control on frame 7."
        )

        val result = validateMatrix(report, ledger, preciseTruncationPolicy)

        val finding = result.report.findings.single()
        assertTrue(result.rejections.isEmpty())
        assertEquals(2, finding.evidence.size)
        assertEquals(AgentConfidence.High, finding.confidence)
        val exemptions = truncationExemptionLines(result)
        assertEquals(1, exemptions.size)
        assertTrue(exemptions.single().contains("call-expert-trunc"))
    }

    // [matrix 5 case b + 9] Two different truncated sources, both confined, no
    // negative/aggregate text: with no complete evidence anywhere in the
    // finding, the blanket cap stands and no exemption line is recorded.
    @Test
    fun everyCitationFromTruncatedSourcesDowngradesWithoutExemption() {
        val ledger = ledgerWith(truncatedExpertCall(), truncatedSummariesCall())
        val report = reportWith(
            evidence(sourceToolCallId = "call-expert-trunc", frameNumber = 7L),
            evidence(
                sourceToolCallId = "call-summaries-trunc",
                type = AgentEvidenceType.Field,
                frameNumber = 12L,
                field = "ip.src"
            ),
            confidence = AgentConfidence.High
        )

        val result = validateMatrix(report, ledger, preciseTruncationPolicy)

        assertEquals(AgentConfidence.Medium, result.report.findings.single().confidence)
        assertTrue(truncationExemptionLines(result).isEmpty())
        assertTrue(loweredConfidenceLines(result).any { it.contains("finding-1") })
    }

    // [matrix 6] scopeIncomplete stacks on top of a finding whose truncation is
    // fully exempted: the per-conclusion exemption is recorded (the truncation
    // genuinely did not matter for it), yet the global uncertainty still caps.
    @Test
    fun scopeIncompleteCapsEvenFullyExemptedFinding() {
        val ledger = ledgerWith(
            truncatedExpertCall(),
            truncatedSummariesCall(),
            completeOverviewCall()
        )
        val report = reportWith(
            evidence(sourceToolCallId = "call-expert-trunc", frameNumber = 7L),
            evidence(
                sourceToolCallId = "call-summaries-trunc",
                type = AgentEvidenceType.Field,
                frameNumber = 12L,
                field = "ip.src"
            ),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High
        )

        val result = validateMatrix(
            report,
            ledger,
            preciseTruncationPolicy,
            scopeIncomplete = true
        )

        assertEquals(AgentConfidence.Medium, result.report.findings.single().confidence)
        assertEquals(2, truncationExemptionLines(result).size)
        assertTrue(
            result.report.limitations.any { it.contains("did not cover the complete capture") }
        )
    }

    // [matrix 6] A failed call elsewhere in the ledger (never cited) is the
    // third runIncomplete trigger: exemption lines stay, confidence still caps.
    @Test
    fun failedToolCallCapsConfidenceDespiteTruncationExemption() {
        val ledger = ledgerWith(
            truncatedExpertCall(),
            completeOverviewCall(),
            AgentToolCall("call-comm", "get_communication_analysis") to AgentToolResult(
                toolCallId = "call-comm",
                toolName = "get_communication_analysis",
                success = false,
                error = AgentError(AgentErrorCode.TOOL_TIMEOUT, "timed out", retryable = true)
            )
        )
        val report = reportWith(
            evidence(sourceToolCallId = "call-expert-trunc", frameNumber = 7L),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High
        )

        val result = validateMatrix(report, ledger, preciseTruncationPolicy)

        assertEquals(AgentConfidence.Medium, result.report.findings.single().confidence)
        assertEquals(1, truncationExemptionLines(result).size)
        assertTrue(
            result.report.limitations.any {
                it.contains("get_communication_analysis") &&
                    it.contains("did not complete") &&
                    it.contains("TOOL_TIMEOUT")
            }
        )
    }

    // [matrix 7] One trace, two findings: the exempted one keeps High and is the
    // only finding named by the exemption lines; the all-truncated sibling caps.
    @Test
    fun exemptAndDowngradedFindingsCoexistAndOnlyExemptedIsNamed() {
        val ledger = ledgerWith(
            truncatedExpertCall(),
            truncatedSummariesCall(),
            completeOverviewCall()
        )
        val exempt = finding(
            id = "finding-exempt",
            evidence(sourceToolCallId = "call-expert-trunc", frameNumber = 7L),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High
        )
        val capped = finding(
            id = "finding-all-trunc",
            evidence(sourceToolCallId = "call-expert-trunc", frameNumber = 7L),
            evidence(
                sourceToolCallId = "call-summaries-trunc",
                type = AgentEvidenceType.Field,
                frameNumber = 12L,
                field = "ip.src"
            ),
            confidence = AgentConfidence.High
        )

        val result = validateMatrix(reportWithFindings(exempt, capped), ledger, preciseTruncationPolicy)

        assertEquals(
            AgentConfidence.High,
            result.report.findings.single { it.id == "finding-exempt" }.confidence
        )
        assertEquals(
            AgentConfidence.Medium,
            result.report.findings.single { it.id == "finding-all-trunc" }.confidence
        )
        val exemptions = truncationExemptionLines(result)
        assertEquals(1, exemptions.size)
        assertTrue(exemptions.single().contains("finding-exempt"))
        assertTrue(exemptions.none { it.contains("finding-all-trunc") })
    }

    // [matrix 8] Rollback: with the switch off the legacy blanket rule applies
    // uniformly across the matrix fixtures — confined-but-truncated caps, all
    // cases behave exactly as before OPT-VAL-07-01, and no exemption line ever
    // appears.  Fixtures untouched by truncation keep High under both settings.
    @Test
    fun rollbackSwitchReproducesLegacyCapsAcrossMatrixFixtures() {
        val confinedLedger = ledgerWith(
            truncatedExpertCall(),
            truncatedSummariesCall(),
            completeOverviewCall()
        )
        val confinedReport = reportWith(
            evidence(sourceToolCallId = "call-expert-trunc", frameNumber = 7L),
            evidence(
                sourceToolCallId = "call-summaries-trunc",
                type = AgentEvidenceType.Field,
                frameNumber = 12L,
                field = "ip.src"
            ),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High
        )
        val confinedOff = validateMatrix(confinedReport, confinedLedger, legacyTruncationPolicy)
        assertEquals(AgentConfidence.Medium, confinedOff.report.findings.single().confidence)
        assertTrue(truncationExemptionLines(confinedOff).isEmpty())

        val allTruncLedger = ledgerWith(truncatedExpertCall(), truncatedSummariesCall())
        val allTruncReport = reportWith(
            evidence(sourceToolCallId = "call-expert-trunc", frameNumber = 7L),
            evidence(
                sourceToolCallId = "call-summaries-trunc",
                type = AgentEvidenceType.Field,
                frameNumber = 12L,
                field = "ip.src"
            ),
            confidence = AgentConfidence.High
        )
        val allTruncOff = validateMatrix(allTruncReport, allTruncLedger, legacyTruncationPolicy)
        val allTruncOn = validateMatrix(allTruncReport, allTruncLedger, preciseTruncationPolicy)
        assertEquals(AgentConfidence.Medium, allTruncOff.report.findings.single().confidence)
        assertEquals(
            allTruncOff.report.findings.single().confidence,
            allTruncOn.report.findings.single().confidence
        )
        assertTrue(truncationExemptionLines(allTruncOff).isEmpty())

        val cleanLedger = ledgerWith(
            call("call-expert", "get_expert_info", data = mapOf("items" to listOf(mapOf("frameNumber" to 7L)))),
            completeOverviewCall()
        )
        val cleanReport = reportWith(
            evidence(sourceToolCallId = "call-expert", frameNumber = 7L),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High
        )
        val cleanOn = validateMatrix(cleanReport, cleanLedger, preciseTruncationPolicy)
        val cleanOff = validateMatrix(cleanReport, cleanLedger, legacyTruncationPolicy)
        assertEquals(AgentConfidence.High, cleanOff.report.findings.single().confidence)
        assertEquals(
            cleanOn.report.findings.single().confidence,
            cleanOff.report.findings.single().confidence
        )
        assertTrue(truncationExemptionLines(cleanOff).isEmpty())
    }

    // [matrix 9] Zero tolerance for unsupported High (mirrors the counter in
    // AgentEvaluationRunner.evaluateRun that feeds the `== 0` release gate in
    // AgentReleaseGate and AgentGoldenCaptureTest): neither a finding with no
    // verifiable evidence nor one resting entirely on truncated reads may leave
    // validation at High, however the precise-truncation path is configured.
    // An exempted High must always have a complete-source citation behind it.
    @Test
    fun highConfidenceFindingsNeverSurviveWithoutCompleteVerifiableEvidence() {
        // (a) High claim, every citation fabricated: evidence removed, Low floor.
        val ledgerA = ledgerWith(truncatedExpertCall())
        val reportA = reportWith(
            evidence(sourceToolCallId = "call-expert-trunc", frameNumber = 424L),
            confidence = AgentConfidence.High
        )
        val resultA = validateMatrix(reportA, ledgerA, preciseTruncationPolicy)
        val findingA = resultA.report.findings.single()
        assertEquals(AgentConfidence.Low, findingA.confidence)
        assertTrue(findingA.conclusion.startsWith("Unverified hypothesis:"))
        assertEquals(0, unsupportedHighConfidenceFindings(resultA, ledgerA))

        // (b) High claim, citations confined but exclusively truncated sources.
        val ledgerB = ledgerWith(truncatedExpertCall(), truncatedSummariesCall())
        val reportB = reportWith(
            evidence(sourceToolCallId = "call-expert-trunc", frameNumber = 7L),
            evidence(
                sourceToolCallId = "call-summaries-trunc",
                type = AgentEvidenceType.Field,
                frameNumber = 12L,
                field = "ip.src"
            ),
            confidence = AgentConfidence.High
        )
        val resultB = validateMatrix(reportB, ledgerB, preciseTruncationPolicy)
        assertEquals(AgentConfidence.Medium, resultB.report.findings.single().confidence)
        assertEquals(0, unsupportedHighConfidenceFindings(resultB, ledgerB))

        // (c) The exemption route that *does* keep High is always backed by a
        // complete source among the surviving citations.
        val ledgerC = ledgerWith(truncatedExpertCall(), completeOverviewCall())
        val reportC = reportWith(
            evidence(sourceToolCallId = "call-expert-trunc", frameNumber = 7L),
            evidence(
                sourceToolCallId = "call-overview",
                type = AgentEvidenceType.Statistic,
                metric = "protocolHierarchy",
                observedValue = "tcp"
            ),
            confidence = AgentConfidence.High
        )
        val resultC = validateMatrix(reportC, ledgerC, preciseTruncationPolicy)
        assertEquals(0, unsupportedHighConfidenceFindings(resultC, ledgerC))
        assertTrue(
            resultC.report.findings.single().evidence.any {
                ledgerC.find(it.sourceToolCallId)?.complete == true
            }
        )
    }

    // ---------------------------------------------------------------- coverage

    /**
     * OPT-VAL-01-01: `ReportCoverageValidator` runs through the same
     * `validate()` entry and the same `report.limitations` channel as every
     * other host-authored line — no rejections, no downgrades, no new channel.
     */
    @Test
    fun unexecutedDeclaredPlanStepsBecomeReportLimitationsThroughValidate() {
        val result = validateWithPlan(
            stopReason = AgentStopReason.MaxStepsReached,
            plan = coveragePlan,
            completedPlanStepIndices = setOf(0)
        )
        val limitations = result.report.limitations
        val gapLine =
            "Plan step \"get_expert_info\" (check TCP retransmissions) was not " +
                "executed before the run stopped (MaxStepsReached)."
        assertTrue(limitations.contains(gapLine))
        // Ordered right after the stop-reason line it qualifies.
        val stepLimitIndex = limitations.indexOfFirst { it.contains("step limit") }
        assertTrue(stepLimitIndex >= 0 && limitations.indexOf(gapLine) > stepLimitIndex)
        assertTrue(result.rejections.isEmpty())
        assertTrue(result.downgrades.isEmpty())
    }

    @Test
    fun modelFinalRunsKeepSilentAboutCoverageGapsThroughValidate() {
        // Pinned choice: the gate is the stop reason, so a voluntary early
        // finalize adds nothing (see ReportCoverageValidatorTest for the
        // same rule at the pure-class level).
        val result = validateWithPlan(
            stopReason = AgentStopReason.ModelFinal,
            plan = coveragePlan,
            completedPlanStepIndices = setOf(0)
        )
        assertTrue(
            result.report.limitations.none { it.contains("was not executed before the run stopped") }
        )
    }

    @Test
    fun tracesWithoutADeclaredPlanGainNothingThroughValidate() {
        val result = validateWithPlan(
            stopReason = AgentStopReason.MaxStepsReached,
            plan = null,
            completedPlanStepIndices = emptySet()
        )
        assertTrue(result.report.limitations.none { it.contains("Plan step") })
    }

    private val coveragePlan = AgentAnalysisPlan(
        goal = "Inspect the trace",
        steps = listOf(
            AgentAnalysisPlanStep("get_capture_overview", "establish the baseline"),
            AgentAnalysisPlanStep("get_expert_info", "check TCP retransmissions")
        )
    )

    private fun validateWithPlan(
        stopReason: AgentStopReason,
        plan: AgentAnalysisPlan?,
        completedPlanStepIndices: Set<Int>
    ): EvidenceValidationResult = EvidenceValidator { FIXED_NOW }.validate(
        report = AgentReport(summary = "A summary.", findings = emptyList()),
        trace = AgentRunTrace(
            snapshot = snapshot(1_000),
            ledger = EvidenceLedger(),
            stopReason = stopReason,
            budgetUsage = AgentBudgetUsage(steps = 2, maxSteps = 12),
            declaredPlan = plan,
            completedPlanStepIndices = completedPlanStepIndices
        )
    )

    // ------------------------------------------------------------ matrix helpers

    private fun validateMatrix(
        report: AgentReport,
        ledger: EvidenceLedger,
        policy: AgentPolicy,
        stopReason: AgentStopReason = AgentStopReason.ModelFinal,
        scopeIncomplete: Boolean = false,
        frameCount: Int = 1_000
    ): EvidenceValidationResult = EvidenceValidator(policy = policy, clock = { FIXED_NOW }).validate(
        report = report,
        trace = AgentRunTrace(
            snapshot = snapshot(frameCount),
            ledger = ledger,
            stopReason = stopReason,
            budgetUsage = AgentBudgetUsage(steps = 2, maxSteps = 12),
            scopeIncomplete = scopeIncomplete
        )
    )

    private fun finding(
        id: String,
        vararg evidenceItems: AgentEvidence,
        title: String = "A finding",
        confidence: AgentConfidence = AgentConfidence.Medium,
        conclusion: String = "A conclusion."
    ) = AgentFinding(
        id = id,
        title = title,
        severity = AgentFindingSeverity.Info,
        confidence = confidence,
        conclusion = conclusion,
        evidence = evidenceItems.toList()
    )

    private fun reportWithFindings(vararg findings: AgentFinding) = AgentReport(
        summary = "A summary.",
        findings = findings.toList()
    )

    private fun truncatedExpertCall(
        toolCallId: String = "call-expert-trunc",
        frames: List<Long> = listOf(7L),
        returnedCount: Long = 100L,
        totalCount: Long = 500L,
        extraData: Map<String, Any?> = emptyMap()
    ): Pair<AgentToolCall, AgentToolResult> {
        val data: Map<String, Any?> = mapOf(
            "items" to frames.map { mapOf("frameNumber" to it) }
        ) + extraData
        return AgentToolCall(toolCallId, "get_expert_info") to successResult(
            toolCallId,
            "get_expert_info",
            data,
            returnedCount = returnedCount,
            totalCount = totalCount,
            truncated = true
        )
    }

    private fun truncatedSummariesCall(): Pair<AgentToolCall, AgentToolResult> =
        AgentToolCall("call-summaries-trunc", "query_packet_summaries") to successResult(
            "call-summaries-trunc",
            "query_packet_summaries",
            mapOf("frames" to listOf(12L), "fields" to listOf("ip.src")),
            returnedCount = 20L,
            totalCount = 80L,
            truncated = true
        )

    private fun completeOverviewCall(): Pair<AgentToolCall, AgentToolResult> =
        call(
            "call-overview",
            "get_capture_overview",
            data = mapOf("protocolHierarchy" to listOf("tcp"))
        )

    /** The stable marker shared by every exemption limitation line. */
    private fun truncationExemptionLines(result: EvidenceValidationResult): List<String> =
        result.report.limitations.filter { it.contains("cites only data") }

    private fun loweredConfidenceLines(result: EvidenceValidationResult): List<String> =
        result.downgrades.filter { it.contains("Lowered confidence") }

    /**
     * Mirror of the unsupported-high-confidence counter in
     * `AgentEvaluationRunner.evaluateRun` (its only input is the *validated*
     * report; `AgentReleaseGate` then requires the count to be zero).  A High
     * finding is unsupported when none of its citations points into what a
     * successful call in this run actually returned.
     */
    private fun unsupportedHighConfidenceFindings(
        result: EvidenceValidationResult,
        ledger: EvidenceLedger
    ): Int = result.report.findings.count { finding ->
        finding.confidence == AgentConfidence.High &&
            finding.evidence.none { evidenceItem ->
                val entry = ledger.find(evidenceItem.sourceToolCallId.trim())
                val frame = evidenceItem.frameNumber
                entry != null && entry.success &&
                    (frame == null || frame in entry.frameNumbers)
            }
    }

    // -------------------------------------------------------------- utilities

    private fun validate(
        report: AgentReport,
        ledger: EvidenceLedger,
        stopReason: AgentStopReason = AgentStopReason.ModelFinal,
        frameCount: Int = 1_000
    ) = EvidenceValidator { FIXED_NOW }.validate(
        report = report,
        trace = AgentRunTrace(
            snapshot = snapshot(frameCount),
            ledger = ledger,
            stopReason = stopReason,
            budgetUsage = AgentBudgetUsage(steps = 2, maxSteps = 12)
        )
    )

    private fun validateWithPolicy(
        report: AgentReport,
        ledger: EvidenceLedger,
        policy: AgentPolicy,
        stopReason: AgentStopReason = AgentStopReason.ModelFinal,
        frameCount: Int = 1_000
    ) = EvidenceValidator(policy = policy, clock = { FIXED_NOW }).validate(
        report = report,
        trace = AgentRunTrace(
            snapshot = snapshot(frameCount),
            ledger = ledger,
            stopReason = stopReason,
            budgetUsage = AgentBudgetUsage(steps = 2, maxSteps = 12)
        )
    )

    private fun snapshot(frameCount: Int) = AgentCaptureSnapshot(
        sessionHandle = 1L,
        fileFingerprint = "sha-test",
        frameCount = frameCount,
        displayFilter = "",
        scope = AnalysisScope.CompleteFile,
        startedAtMillis = FIXED_NOW,
        analysisGeneration = 1L,
        sessionGeneration = 1L,
        agentGeneration = 1L
    )

    private fun reportWith(
        vararg evidence: AgentEvidence,
        confidence: AgentConfidence = AgentConfidence.Medium,
        severity: AgentFindingSeverity = AgentFindingSeverity.Info,
        conclusion: String = "A conclusion."
    ) = AgentReport(
        summary = "A summary.",
        findings = listOf(
            AgentFinding(
                id = "finding-1",
                title = "A finding",
                severity = severity,
                confidence = confidence,
                conclusion = conclusion,
                evidence = evidence.toList()
            )
        )
    )

    private fun evidence(
        sourceToolCallId: String,
        type: AgentEvidenceType = AgentEvidenceType.ExpertInfo,
        frameNumber: Long? = null,
        displayFilter: String? = null,
        field: String? = null,
        metric: String? = null,
        observedValue: String? = null,
        observation: String = "Something was observed.",
        timeRangeStartMillis: Long? = null,
        timeRangeEndMillis: Long? = null
    ) = AgentEvidence(
        type = type,
        frameNumber = frameNumber,
        displayFilter = displayFilter,
        field = field,
        observation = observation,
        sourceToolCallId = sourceToolCallId,
        metric = metric,
        observedValue = observedValue,
        timeRangeStartMillis = timeRangeStartMillis,
        timeRangeEndMillis = timeRangeEndMillis
    )

    private fun ledgerWith(vararg entries: Pair<AgentToolCall, AgentToolResult>) =
        EvidenceLedger().apply {
            entries.forEachIndexed { index, (call, result) ->
                record(call, result, stepIndex = index + 1)
            }
        }

    private fun call(
        toolCallId: String,
        toolName: String,
        arguments: Map<String, Any?> = emptyMap(),
        data: Map<String, Any?>
    ): Pair<AgentToolCall, AgentToolResult> =
        AgentToolCall(toolCallId, toolName, arguments) to successResult(toolCallId, toolName, data)

    private fun successResult(
        toolCallId: String,
        toolName: String,
        data: Map<String, Any?>,
        returnedCount: Long = 1L,
        totalCount: Long = 1L,
        truncated: Boolean = false
    ) = AgentToolResult(
        toolCallId = toolCallId,
        toolName = toolName,
        success = true,
        data = data,
        truncated = truncated,
        provenance = AgentProvenance(
            toolName = toolName,
            returnedCount = returnedCount,
            totalCount = totalCount,
            truncated = truncated
        ),
        returnedCount = returnedCount,
        totalCount = totalCount
    )

    // ------------------------------------------------- OPT-VAL-02-03 rule 3 net

    private fun validateWithSignals(
        report: AgentReport,
        signals: List<AgentSignal>,
        policy: AgentPolicy = AgentPolicy(),
        criticAddressedSignalIds: Set<String> = emptySet()
    ): EvidenceValidationResult = EvidenceValidator(
        policy = policy,
        clock = { FIXED_NOW }
    ).validate(
        report = report,
        trace = AgentRunTrace(
            snapshot = snapshot(1_000),
            ledger = EvidenceLedger(),
            stopReason = AgentStopReason.ModelFinal,
            budgetUsage = AgentBudgetUsage(steps = 2, maxSteps = 12),
            signals = signals,
            criticAddressedSignalIds = criticAddressedSignalIds
        )
    )

    private val netSignals = listOf(
        AgentSignal("sig-net000000001", AgentSignalExtractor.KIND_HEALTH_PROBLEMS, "3", "problems"),
        AgentSignal("sig-net000000002", AgentSignalExtractor.KIND_EXPERT_GROUP, "12", "items"),
        AgentSignal("sig-net000000003", AgentSignalExtractor.KIND_PROTOCOL_SHARE, "61.000", "percent")
    )

    private fun signalGapLines(result: EvidenceValidationResult): List<String> =
        result.report.limitations.filter {
            it.startsWith(ReportCoverageValidator.SIGNAL_GAP_LIMITATION_MARKER)
        }

    @Test
    fun traceSignalsAddressedByNothingGainOneLimitationEachThroughValidate() {
        // The post-validation net: the submit gate counted one finding as
        // coverage, validation stripped every finding, and the final report
        // still answers for each enumerated signal.  Pinned wording:
        // identical to the helper the gate's degradation path shares.
        val result = validateWithSignals(
            report = AgentReport(summary = "A summary.", findings = emptyList()),
            signals = netSignals.take(2)
        )
        assertEquals(
            listOf(
                "Host-enumerated overview signal sig-net000000001 " +
                    "(health_problems 3 problems) was not addressed by any finding.",
                "Host-enumerated overview signal sig-net000000002 " +
                    "(expert_group 12 items) was not addressed by any finding."
            ),
            signalGapLines(result)
        )
    }

    @Test
    fun findingsLimitationsAndCriticDispositionsAllCloseTheNet() {
        // Every §5.2 addressing channel, one signal each — none of the three
        // may narrate a gap.
        val result = validateWithSignals(
            report = AgentReport(
                summary = "A summary.",
                findings = listOf(
                    finding("f-covered", title = "Cited a signal")
                        .copy(relatedSignals = listOf("sig-net000000001"))
                ),
                limitations = listOf(
                    "sig-net000000002 was reviewed against the display filter and is benign."
                )
            ),
            signals = netSignals,
            criticAddressedSignalIds = setOf("sig-net000000003")
        )
        assertEquals(emptyList<String>(), signalGapLines(result))
    }

    @Test
    fun markerPrefixedLimitationsNeverSatisfyTheNetOnALaterRound() {
        // A report re-validated after a first round — revision, reconcile —
        // already carries the host's own gap lines in `limitations`.
        // Counting them would silently close the very gaps they report.
        val carried = ReportCoverageValidator().signalGapLimitation(netSignals.first())
        val result = validateWithSignals(
            report = AgentReport(
                summary = "A summary.",
                findings = emptyList(),
                limitations = listOf(carried)
            ),
            signals = listOf(netSignals.first())
        )
        // Exactly one line: the set-based channel dedupes, and the carried
        // line did not address the signal it names.
        assertEquals(listOf(carried), signalGapLines(result))
    }

    @Test
    fun signalCoverageValveOffSilencesTheNet() {
        val result = validateWithSignals(
            report = AgentReport(summary = "A summary.", findings = emptyList()),
            signals = netSignals,
            policy = AgentPolicy(enforceSignalCoverage = false)
        )
        assertEquals(emptyList<String>(), signalGapLines(result))
    }

    private companion object {
        const val FIXED_NOW = 1_700_000_000_000L
    }
}
