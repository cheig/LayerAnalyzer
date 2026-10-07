// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketRepositoryParsingTest {
    @Test
    fun protocolNodeDefaultsMissingOptionalFields() {
        val root = PacketRepository().parseProtocolNode(
            JSONObject(
                """
                {
                  "label": "IPv4",
                  "children": [
                    { "label": "Source", "value": "192.0.2.1" },
                    {}
                  ]
                }
                """.trimIndent()
            )
        )

        assertEquals("IPv4", root.label)
        assertNull(root.value)
        assertNull(root.filter)
        assertEquals("none", root.severity)
        assertFalse(root.generated)
        assertEquals(2, root.children.size)
        assertEquals("Source", root.children[0].label)
        assertEquals("192.0.2.1", root.children[0].value)
        assertEquals("Unknown", root.children[1].label)
    }

    @Test
    fun enhancedCommunicationJsonParsesSipMetadataWithoutAuthorizationValue() {
        val analysis = PacketRepository().parseCommunicationAnalysis(
            JSONObject(
                """
                {
                  "schemaVersion": 2,
                  "sipMessages": [{
                    "frameNumber": 10, "time": 1.5, "source": "192.0.2.1", "destination": "192.0.2.2",
                    "method": "INVITE", "callId": "call-1", "cSeqNumber": 42, "cSeqMethod": "INVITE",
                    "viaBranch": "z9hG4bK-one", "fromTag": "from-one", "toTag": "to-one",
                    "requestUri": "sip:bob@example.invalid", "authorizationPresent": true,
                    "authorizationScheme": "Digest", "contentType": "application/sdp",
                    "hasCSeqNumber": true, "hasCSeqMethod": true, "hasViaBranch": true,
                    "hasFromTag": true, "hasToTag": true, "hasRequestUri": true, "hasAuthorization": true,
                    "hasContentType": true, "hasSdp": true, "sdpMediaType": "audio", "sdpMediaPort": 4000,
                    "sdpDirection": "sendrecv", "sdpOfferAnswerRole": "offer", "hasSdpDirection": true,
                    "hasSdpOfferAnswerRole": true,
                    "sdpPayloadMappings": [{"payloadType": 96, "encodingName": "OPUS", "clockRate": 48000,
                      "channels": 2, "fmtpParameters": ["minptime", "useinbandfec"]}],
                    "info": "INVITE"
                  }],
                  "rtpPackets": [], "rtcpPackets": [], "coreMessages": []
                }
                """.trimIndent()
            )
        )

        val message = analysis.sipMessages.single()
        assertEquals(2, analysis.schemaVersion)
        assertEquals(42L, message.cSeqNumber)
        assertEquals("Digest", message.authorizationScheme)
        assertTrue(message.authorizationPresent)
        assertTrue(message.fieldPresence.viaBranch)
        assertEquals("sendrecv", message.sdp?.direction?.wireValue)
        assertEquals(96, message.sdp?.payloadMappings?.single()?.payloadType)
        assertEquals(listOf("minptime", "useinbandfec"), message.sdp?.payloadMappings?.single()?.fmtpParameters)
        assertFalse(analysis.toString().contains("username="))
    }

    @Test
    fun oldCommunicationJsonUsesSafeDefaultsForNewFields() {
        val analysis = PacketRepository().parseCommunicationAnalysis(
            JSONObject("""{"sipMessages":[{"frameNumber":1,"time":0,"source":"a","destination":"b","method":"OPTIONS"}]}""")
        )

        val message = analysis.sipMessages.single()
        assertEquals(1, analysis.schemaVersion)
        assertNull(message.cSeqNumber)
        assertNull(message.viaBranch)
        assertFalse(message.authorizationPresent)
        assertFalse(message.fieldPresence.cSeqNumber)
    }

    @Test
    fun coreCommunicationJsonParsesCorrelationFactsAndPartialState() {
        val analysis = PacketRepository().parseCommunicationAnalysis(
            JSONObject(
                """
                {
                  "schemaVersion": 3,
                  "coreTotal": 2,
                  "coreTruncated": true,
                  "coreMessages": [{
                    "frameNumber": 20, "time": 2.0, "protocol": "PFCP",
                    "source": "192.0.2.1", "destination": "192.0.2.2",
                    "correlationField": "pfcp.seid", "correlationValue": "42",
                    "messageType": "Session Establishment Request", "outcome": "",
                    "info": "Session Establishment Request", "commandCode": null,
                    "applicationId": null, "request": true, "sessionId": "",
                    "sequenceNumber": 7, "cause": "", "seid": "42", "teid": "",
                    "apnOrDnn": "internet",
                    "fields": {"pfcp.seid": "42", "pfcp.sequenceNumber": "7"},
                    "identifiers": {"pfcp.seid": "42", "apnOrDnn": "internet"},
                    "fieldPresence": ["pfcp.seid", "pfcp.sequenceNumber", "apnOrDnn"]
                  }, {
                    "frameNumber": 21, "time": 2.1, "protocol": "PFCP",
                    "source": "192.0.2.2", "destination": "192.0.2.1",
                    "correlationField": "pfcp.seid", "correlationValue": "42",
                    "messageType": "Session Establishment Response", "outcome": "1",
                    "info": "Session Establishment Response", "seid": "42",
                    "fields": {"pfcp.seid": "42"},
                    "identifiers": {"pfcp.seid": "42"},
                    "fieldPresence": ["pfcp.seid"]
                  }]
                }
                """.trimIndent()
            )
        )

        assertEquals(3, analysis.schemaVersion)
        assertEquals(2, analysis.coreTotal)
        assertTrue(analysis.coreTruncated)
        assertEquals(2, analysis.coreMessages.size)
        assertEquals(7L, analysis.coreMessages.first().sequenceNumber)
        assertEquals("internet", analysis.coreMessages.first().apnOrDnn)
        assertEquals("42", analysis.coreMessages.first().fields["pfcp.seid"])
        assertTrue("pfcp.seid" in analysis.coreMessages.first().fieldPresence)
        assertTrue(analysis.coreSessions.single().partial)
    }

    @Test
    fun scopedSummaryQueryJsonPreservesPagingAndPacketOrder() {
        val query = PacketRepository().parseScopedPacketSummaryQuery(
            JSONObject(
                """
                {
                  "success": true,
                  "items": [
                    {"frameNumber": 8, "time": 12.5, "source": "a", "destination": "b",
                     "protocol": "UDP", "length": 64, "sourcePort": 5060,
                     "destinationPort": 5061, "info": "SIP"}
                  ],
                  "offset": 7,
                  "returned": 1,
                  "total": 9,
                  "truncated": true,
                  "cancelled": false,
                  "queryVersion": "native-scoped-v1"
                }
                """.trimIndent()
            )
        )

        assertTrue(query.success)
        assertEquals(7, query.offset)
        assertEquals(1, query.returned)
        assertEquals(9, query.total)
        assertTrue(query.truncated)
        assertFalse(query.cancelled)
        assertEquals("native-scoped-v1", query.queryVersion)
        assertEquals(8L, query.items.single().frameNumber)
        assertEquals("12.500000", query.items.single().time)
        assertEquals(5060, query.items.single().sourcePort)
    }

    @Test
    fun scopedSummaryQueryJsonDefaultsMissingOptionalValuesSafely() {
        val query = PacketRepository().parseScopedPacketSummaryQuery(
            JSONObject("""{"success":false,"error":"Invalid display filter.","items":[]}""")
        )

        assertFalse(query.success)
        assertEquals("Invalid display filter.", query.error)
        assertEquals(0, query.offset)
        assertTrue(query.items.isEmpty())
        assertFalse(query.cancelled)
    }
}
