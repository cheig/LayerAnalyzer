// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.CoreCorrelationConfidence
import com.example.layanalyzer.model.CoreCorrelationEdgeType
import com.example.layanalyzer.model.CoreSignalMessage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CoreCorrelationEngineTest {

    @Test
    fun diameterSessionIdConnectsRequestAndResponseAcrossFieldShapes() {
        val result = CoreCorrelationEngine.correlate(
            listOf(
                signal(
                    frame = 10,
                    time = 1.0,
                    protocol = "DIAMETER",
                    correlationField = "diameter.session-id",
                    correlationValue = "session-1",
                    messageType = "CCR",
                    commandCode = 272,
                    request = true
                ),
                signal(
                    frame = 11,
                    time = 1.1,
                    protocol = "DIAMETER",
                    messageType = "CCA",
                    outcome = "2001",
                    sessionId = "session-1",
                    commandCode = 272,
                    request = false
                )
            )
        )

        val timeline = result.timelines.single()
        assertEquals(2, timeline.messages.size)
        assertEquals(CoreCorrelationConfidence.High, timeline.correlationQuality)
        assertTrue(timeline.edges.any {
            it.type == CoreCorrelationEdgeType.SameSessionId &&
                it.basisFields.any { field -> field.contains("session", ignoreCase = true) } &&
                "diameter.commandCode" in it.basisFields
        })
    }

    @Test
    fun pfcpAndGtpUseTheirSessionIdentifiersWithoutColliding() {
        val result = CoreCorrelationEngine.correlate(
            listOf(
                signal(1, 1.0, "PFCP", messageType = "Session Establishment Request", seid = "100"),
                signal(2, 1.1, "PFCP", messageType = "Session Establishment Response", seid = "100"),
                signal(3, 1.2, "GTPv2", messageType = "Create Session Request", teid = "200"),
                signal(4, 1.3, "GTPv2", messageType = "Create Session Response", teid = "200")
            )
        )

        assertEquals(2, result.timelines.size)
        assertEquals(2, result.timelines.first { it.messages.first().protocol == "PFCP" }.messages.size)
        assertEquals(2, result.timelines.first { it.messages.first().protocol == "GTPv2" }.messages.size)
        assertTrue(result.timelines.flatMap { it.edges }.any { it.type == CoreCorrelationEdgeType.SameTeid })
        assertTrue(result.timelines.flatMap { it.edges }.any { it.type == CoreCorrelationEdgeType.SameSessionId })
    }

    @Test
    fun s1apAndNgapUeIdentifiersRemainStableWithinTheirNamespaces() {
        val result = CoreCorrelationEngine.correlate(
            listOf(
                signal(
                    1,
                    1.0,
                    "S1AP",
                    messageType = "Initial UE Message",
                    fields = mapOf("s1ap.mmeUeId" to "10", "s1ap.enbUeId" to "20")
                ),
                signal(
                    2,
                    1.1,
                    "S1AP",
                    messageType = "Downlink NAS Transport",
                    fields = mapOf("s1ap.mmeUeId" to "10")
                ),
                signal(
                    3,
                    1.2,
                    "NGAP",
                    messageType = "Initial UE Message",
                    fields = mapOf("ngap.amfUeId" to "30", "ngap.ranUeId" to "40")
                ),
                signal(
                    4,
                    1.3,
                    "NGAP",
                    messageType = "Downlink NAS Transport",
                    fields = mapOf("ngap.amfUeId" to "30")
                )
            )
        )

        assertEquals(2, result.timelines.size)
        assertTrue(result.timelines.all { it.messages.size == 2 })
        assertTrue(result.timelines.all { timeline ->
            timeline.edges.any { it.type == CoreCorrelationEdgeType.SameUeId }
        })
    }

    @Test
    fun nasProcedureTransactionIdentityCarriesFailureCauseIntoProcedure() {
        val result = CoreCorrelationEngine.correlate(
            listOf(
                signal(
                    1,
                    1.0,
                    "NAS-EPS",
                    messageType = "Attach Request",
                    request = true,
                    procedureTransactionIdentity = 7
                ),
                signal(
                    2,
                    1.2,
                    "NAS-EPS",
                    messageType = "Attach Reject",
                    outcome = "reject",
                    cause = "15",
                    request = false,
                    procedureTransactionIdentity = 7
                )
            )
        )

        val timeline = result.timelines.single()
        assertEquals("registration_attach", timeline.procedureType)
        assertTrue(timeline.failureCauses.contains("15"))
        assertTrue(timeline.edges.any { it.type == CoreCorrelationEdgeType.SameSequence })
        assertTrue(timeline.stages.single().causes.contains("15"))
    }

    @Test
    fun conflictingSubscriberIdentifiersPreventSameSequenceCrossTalk() {
        val result = CoreCorrelationEngine.correlate(
            listOf(
                signal(
                    1,
                    1.0,
                    "GTPv2",
                    messageType = "Create Session Request",
                    sequenceNumber = 9,
                    fields = mapOf("subscriber.id" to "imsi-a")
                ),
                signal(
                    2,
                    1.1,
                    "GTPv2",
                    messageType = "Create Session Request",
                    sequenceNumber = 9,
                    fields = mapOf("subscriber.id" to "imsi-b")
                )
            )
        )

        assertEquals(2, result.timelines.size)
        assertTrue(result.graph.edges.none { it.type == CoreCorrelationEdgeType.SameSequence })
        assertTrue(result.timelines.all { it.correlationQuality == CoreCorrelationConfidence.Weak })
    }

    @Test
    fun temporalOnlyAssociationIsWeakAndDoesNotMergeComponents() {
        val result = CoreCorrelationEngine.correlate(
            listOf(
                signal(1, 1.0, "NAS-EPS", messageType = "Unknown"),
                signal(2, 1.5, "NAS-EPS", messageType = "Unknown")
            )
        )

        assertEquals(2, result.timelines.size)
        assertTrue(result.graph.edges.any { it.type == CoreCorrelationEdgeType.TimeAdjacent })
        assertTrue(result.timelines.all { it.correlationQuality == CoreCorrelationConfidence.Weak })
        assertTrue(result.timelines.all { timeline ->
            timeline.limitations.any { it.contains("Weak", ignoreCase = true) }
        })
    }

    @Test
    fun truncatedInputMarksTimelinePartial() {
        val result = CoreCorrelationEngine.correlate(
            listOf(signal(1, 1.0, "PFCP", seid = "100")),
            sourceTruncated = true
        )

        assertTrue(result.timelines.single().partial)
        assertTrue(result.timelines.single().limitations.any { it.contains("Partial") })
    }

    private fun signal(
        frame: Long,
        time: Double,
        protocol: String,
        correlationField: String = "",
        correlationValue: String = "",
        messageType: String = "",
        outcome: String = "",
        cause: String = "",
        request: Boolean? = null,
        commandCode: Int? = null,
        sessionId: String = "",
        seid: String = "",
        teid: String = "",
        sequenceNumber: Long? = null,
        procedureTransactionIdentity: Int? = null,
        fields: Map<String, String> = emptyMap()
    ) = CoreSignalMessage(
        frameNumber = frame,
        time = time,
        protocol = protocol,
        source = "10.0.0.1",
        destination = "10.0.0.2",
        correlationField = correlationField,
        correlationValue = correlationValue,
        messageType = messageType,
        outcome = outcome,
        info = messageType,
        request = request,
        commandCode = commandCode,
        sessionId = sessionId,
        seid = seid,
        teid = teid,
        sequenceNumber = sequenceNumber,
        procedureTransactionIdentity = procedureTransactionIdentity,
        cause = cause,
        fields = fields
    )
}
