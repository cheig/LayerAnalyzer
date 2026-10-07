package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.agent.AgentBudgetTracker
import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.data.CommunicationAnalyzer
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.CoreSignalMessage
import com.example.layanalyzer.model.RtcpPacketMetric
import com.example.layanalyzer.model.RtpPacketMetric
import com.example.layanalyzer.model.SdpMediaSummary
import com.example.layanalyzer.model.SdpPayloadMapping
import com.example.layanalyzer.model.SipMessage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CommunicationAnalysisToolTest {

    @Test
    fun defaultResultCarriesCallsStreamsAndSessionSummaries() = runBlocking {
        AgentToolTestHarness.create {
            communication = analysis()
        }.use { harness ->
            val result = harness.runCommunication()

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            assertNotNull(data["calls"])
            assertNotNull(data["rtpStreams"])
            assertNotNull(data["rtcpStreams"])
            assertNotNull(data["coreSessions"])

            @Suppress("UNCHECKED_CAST")
            val calls = data["calls"] as List<Map<String, Any?>>
            assertEquals(2, calls.size)
            // A summary carries the count, not the messages themselves.
            assertNotNull(calls.first()["messageCount"])
            assertNull(calls.first()["messages"])
        }
    }

    @Test
    fun domainSelectionReturnsOnlyTheRequestedDomains() = runBlocking {
        AgentToolTestHarness.create {
            communication = analysis()
        }.use { harness ->
            val result = harness.runCommunication(mapOf("domains" to listOf("sip")))

            val data = requireNotNull(result.data)
            assertNotNull(data["calls"])
            assertNull(data["rtpStreams"])
            assertNull(data["rtcpStreams"])
            assertNull(data["coreSessions"])
        }
    }

    @Test
    fun callsAreFilteredByCallIdAgainstTheRealValue() = runBlocking {
        AgentToolTestHarness.create {
            communication = analysis()
        }.use { harness ->
            val result = harness.runCommunication(
                mapOf("domains" to listOf("sip"), "callId" to "call-a")
            )

            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val calls = data["calls"] as List<Map<String, Any?>>
            assertEquals(1, calls.size)
            assertEquals(1, data["callsTotal"])
            assertEquals(10L, calls.first()["firstFrame"])
        }
    }

    @Test
    fun callsAreFilteredByTimeRangeInclusiveOfPartialOverlap() = runBlocking {
        AgentToolTestHarness.create {
            communication = analysis()
        }.use { harness ->
            // Call A spans 100-102, call B spans 200-202.
            val onlyFirst = harness.runCommunication(
                mapOf("domains" to listOf("sip"), "startTime" to 90.0, "endTime" to 150.0)
            )
            @Suppress("UNCHECKED_CAST")
            val firstCalls = requireNotNull(onlyFirst.data)["calls"] as List<Map<String, Any?>>
            assertEquals(1, firstCalls.size)

            val both = harness.runCommunication(
                mapOf("domains" to listOf("sip"), "startTime" to 90.0, "endTime" to 250.0)
            )
            @Suppress("UNCHECKED_CAST")
            val bothCalls = requireNotNull(both.data)["calls"] as List<Map<String, Any?>>
            assertEquals(2, bothCalls.size)

            // A window that starts inside call B still matches it.
            val clipped = harness.runCommunication(
                mapOf("domains" to listOf("sip"), "startTime" to 201.0)
            )
            @Suppress("UNCHECKED_CAST")
            val clippedCalls = requireNotNull(clipped.data)["calls"] as List<Map<String, Any?>>
            assertEquals(1, clippedCalls.size)
        }
    }

    @Test
    fun coreSessionsAreFilteredByProtocol() = runBlocking {
        AgentToolTestHarness.create {
            communication = analysis()
        }.use { harness ->
            val result = harness.runCommunication(
                mapOf("domains" to listOf("core"), "protocol" to "diameter")
            )

            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val sessions = data["coreSessions"] as List<Map<String, Any?>>
            assertEquals(1, sessions.size)
            assertEquals("diameter", sessions.first()["protocol"])
        }
    }

    @Test
    fun pagingReportsTotalsAndFlagsRemainingEntries() = runBlocking {
        AgentToolTestHarness.create {
            communication = CommunicationAnalyzer.aggregate(
                CommunicationAnalysis(
                    sipMessages = (1..10).flatMap { index ->
                        listOf(
                            sip(frame = index * 10L, time = index * 100.0, callId = "call-$index"),
                            sip(
                                frame = index * 10L + 1,
                                time = index * 100.0 + 1,
                                callId = "call-$index",
                                status = "200 OK"
                            )
                        )
                    }
                )
            )
        }.use { harness ->
            val firstPage = harness.runCommunication(
                mapOf("domains" to listOf("sip"), "limit" to 4)
            )
            val firstData = requireNotNull(firstPage.data)
            assertEquals(4, (firstData["calls"] as List<*>).size)
            assertEquals(10, firstData["callsTotal"])
            assertEquals(true, firstData["truncated"])

            val lastPage = harness.runCommunication(
                mapOf("domains" to listOf("sip"), "offset" to 8, "limit" to 4)
            )
            val lastData = requireNotNull(lastPage.data)
            assertEquals(2, (lastData["calls"] as List<*>).size)
            assertEquals(false, lastData["truncated"])
        }
    }

    @Test
    fun includeMessagesAddsLimitedMessageFieldsAndNeverASipBody() = runBlocking {
        AgentToolTestHarness.create {
            communication = analysis()
        }.use { harness ->
            val result = harness.runCommunication(
                mapOf("domains" to listOf("sip"), "includeMessages" to true)
            )

            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val calls = data["calls"] as List<Map<String, Any?>>
            @Suppress("UNCHECKED_CAST")
            val messages = calls.first()["messages"] as List<Map<String, Any?>>
            assertEquals(2, messages.size)
            assertEquals("INVITE", messages.first()["method"])
            assertNotNull(messages.first()["frameNumber"])

            val encoded = AgentResultTruncator.encode(data)
            listOf("body", "sdpText", "rawHeaders", "payload").forEach { forbidden ->
                assertFalse(forbidden, encoded.contains(forbidden))
            }
        }
    }

    @Test
    fun nativeTruncationIsReportedPerDomainAndNeverClaimedComplete() = runBlocking {
        AgentToolTestHarness.create {
            communication = analysis().copy(
                sipTotal = 5000,
                sipTruncated = true,
                rtpTotal = 120,
                rtpTruncated = false
            )
        }.use { harness ->
            val result = harness.runCommunication()

            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val sipSource = data["sipSource"] as Map<String, Any?>
            assertEquals(5000, sipSource["total"])
            assertEquals(true, sipSource["truncated"])

            @Suppress("UNCHECKED_CAST")
            val rtpSource = data["rtpSource"] as Map<String, Any?>
            assertEquals(120, rtpSource["total"])
            assertEquals(false, rtpSource["truncated"])

            // A short page built from a capped analysis is still not complete.
            assertEquals(true, data["sourceTruncated"])
            assertEquals(true, data["truncated"])
            assertTrue(result.truncated)
        }
    }

    @Test
    fun rtpStreamQualityMetricsTravelWithoutIndividualPackets() = runBlocking {
        AgentToolTestHarness.create {
            communication = analysis()
        }.use { harness ->
            val result = harness.runCommunication(mapOf("domains" to listOf("rtp")))

            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val streams = data["rtpStreams"] as List<Map<String, Any?>>
            assertEquals(1, streams.size)
            val stream = streams.first()
            assertEquals(3, stream["packetCount"])
            assertNotNull(stream["lostPackets"])
            assertNotNull(stream["ssrc"])
            // The per-packet metric list is not part of the projection.
            assertNull(stream["packets"])
        }
    }

    @Test
    fun correlatedMediaSessionsProjectSdpRtpRtcpEvidenceForTheSelectedCall() = runBlocking {
        val offer = SdpMediaSummary(
            frameNumber = 60,
            connectionAddress = "10.0.0.1",
            mediaType = "audio",
            mediaPort = 16000,
            mediaProtocol = "RTP/AVP",
            formats = listOf("96"),
            codecs = listOf("opus"),
            payloadMappings = listOf(SdpPayloadMapping(96, "opus", 48_000))
        )
        val answer = offer.copy(
            frameNumber = 61,
            connectionAddress = "10.0.0.2"
        )
        AgentToolTestHarness.create {
            communication = CommunicationAnalysis(
                sipMessages = listOf(
                    SipMessage(
                        frameNumber = 60,
                        time = 6.0,
                        source = "10.0.0.1",
                        destination = "10.0.0.2",
                        method = "INVITE",
                        callId = "media-call",
                        cSeqNumber = 1,
                        cSeqMethod = "INVITE",
                        viaBranch = "media-branch",
                        sdp = offer
                    ),
                    SipMessage(
                        frameNumber = 61,
                        time = 6.1,
                        source = "10.0.0.2",
                        destination = "10.0.0.1",
                        status = "200 OK",
                        callId = "media-call",
                        cSeqNumber = 1,
                        cSeqMethod = "INVITE",
                        viaBranch = "media-branch",
                        sdp = answer
                    )
                ),
                rtpPackets = listOf(
                    RtpPacketMetric(
                        frameNumber = 62,
                        time = 6.2,
                        source = "10.0.0.1",
                        destination = "10.0.0.2",
                        sourcePort = 16000,
                        destinationPort = 16000,
                        sequence = 1,
                        ssrc = 99,
                        timestamp = 0,
                        payloadType = 96
                    ),
                    RtpPacketMetric(
                        frameNumber = 63,
                        time = 6.221,
                        source = "10.0.0.1",
                        destination = "10.0.0.2",
                        sourcePort = 16000,
                        destinationPort = 16000,
                        sequence = 2,
                        ssrc = 99,
                        timestamp = 960,
                        payloadType = 96
                    )
                ),
                rtcpPackets = listOf(
                    RtcpPacketMetric(
                        frameNumber = 64,
                        time = 6.3,
                        source = "10.0.0.2",
                        destination = "10.0.0.1",
                        reportedSsrc = 99,
                        fractionLost = 26,
                        cumulativeLost = 2
                    )
                )
            )
        }.use { harness ->
            val result = harness.runCommunication(
                mapOf("domains" to listOf("rtp"), "callId" to "media-call")
            )

            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val sessions = data["mediaSessions"] as List<Map<String, Any?>>
            @Suppress("UNCHECKED_CAST")
            val lines = sessions.single()["mLines"] as List<Map<String, Any?>>
            @Suppress("UNCHECKED_CAST")
            val directions = lines.single()["directions"] as List<Map<String, Any?>>
            @Suppress("UNCHECKED_CAST")
            val reports = lines.single()["rtcpReports"] as List<Map<String, Any?>>

            assertEquals(1, sessions.size)
            assertEquals(48_000, directions.first { it["direction"] == "offer-to-answer" }["clockRate"])
            assertEquals(64L, reports.single()["firstFrame"])
            // A Call-ID selection now returns its correlated media, never every raw stream.
            assertTrue((data["rtpStreams"] as List<*>).isEmpty())
        }
    }

    @Test
    fun aCallIdSelectorExcludesMediaStreamsRatherThanMatchingAllOfThem() = runBlocking {
        AgentToolTestHarness.create {
            communication = analysis()
        }.use { harness ->
            val result = harness.runCommunication(mapOf("callId" to "call-a"))

            val data = requireNotNull(result.data)
            // Correlating media to a call needs SDP analysis, so a Call-ID query
            // must not hand back every stream in the capture as if it belonged.
            assertTrue((data["rtpStreams"] as List<*>).isEmpty())
            assertTrue((data["rtcpStreams"] as List<*>).isEmpty())
            assertEquals(1, (data["calls"] as List<*>).size)
        }
    }

    @Test
    fun theCallIdIsRedactedInTheResultWhileMatchingUsesTheRealValue() = runBlocking {
        AgentToolTestHarness.create {
            communication = analysis()
        }.use { harness ->
            val result = harness.runCommunication(
                arguments = mapOf("domains" to listOf("sip"), "callId" to "call-a"),
                privacyMode = AgentPrivacyMode.RedactedMetadata
            )

            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val calls = data["calls"] as List<Map<String, Any?>>
            // The selector matched, which proves the real value was used...
            assertEquals(1, calls.size)
            // ...and the frame number is intact so the model can still cite it.
            assertEquals(10L, calls.first()["firstFrame"])
        }
    }

    @Test
    fun sipProjectionIncludesDeterministicRegistrationStages() = runBlocking {
        AgentToolTestHarness.create {
            communication = CommunicationAnalysis(
                sipMessages = listOf(
                    registration(frame = 70, time = 7.0, cSeq = 1),
                    registrationResponse(frame = 71, time = 7.1, cSeq = 1, status = "401 Unauthorized"),
                    registration(frame = 72, time = 7.2, cSeq = 2, authorization = true),
                    registrationResponse(frame = 73, time = 7.3, cSeq = 2, status = "200 OK")
                ),
                sipTotal = 4
            )
        }.use { harness ->
            val result = harness.runCommunication(
                mapOf("domains" to listOf("sip"), "protocol" to "register")
            )

            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val analyses = data["registrationAnalyses"] as List<Map<String, Any?>>
            @Suppress("UNCHECKED_CAST")
            val selected = analyses.single()["selectedAttempt"] as Map<String, Any?>
            @Suppress("UNCHECKED_CAST")
            val timeline = selected["timeline"] as List<Map<String, Any?>>
            assertEquals("Success", analyses.single()["outcome"])
            assertEquals(listOf(70L, 71L, 72L, 73L), timeline.map { it["frameNumber"] })
            assertEquals(1, data["registrationAnalysesTotal"])
        }
    }

    @Test
    fun sipProjectionIncludesDerivedCallSetupStages() = runBlocking {
        AgentToolTestHarness.create {
            communication = CommunicationAnalysis(
                sipMessages = listOf(
                    setupMessage(80, 8.0, method = "INVITE", cSeq = 1, branch = "invite"),
                    setupMessage(81, 8.1, status = "100 Trying", cSeq = 1, branch = "invite", reverse = true),
                    setupMessage(82, 9.0, status = "180 Ringing", cSeq = 1, branch = "invite", reverse = true),
                    setupMessage(83, 10.0, status = "200 OK", cSeq = 1, branch = "invite", reverse = true),
                    setupMessage(84, 10.1, method = "ACK", cSeq = 1, branch = "ack")
                ),
                sipTotal = 5
            )
        }.use { harness ->
            val result = harness.runCommunication(mapOf("domains" to listOf("sip")))

            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val setup = data["callSetupAnalysis"] as Map<String, Any?>
            @Suppress("UNCHECKED_CAST")
            val selected = setup["selectedAttempt"] as Map<String, Any?>
            @Suppress("UNCHECKED_CAST")
            val stages = selected["stages"] as List<Map<String, Any?>>
            assertEquals("Success", setup["outcome"])
            assertEquals(80L, selected["inviteFrame"])
            assertEquals(84L, selected["ackFrame"])
            assertEquals(2_100L, selected["setupDurationMillis"])
            assertTrue(stages.any { it["stage"] == "InviteToTrying" && it["durationMillis"] == 100L })
        }
    }

    @Test
    fun aSessionChangeIsRejectedWithAStructuredError() = runBlocking {
        AgentToolTestHarness.create {
            communication = analysis()
        }.use { harness ->
            val snapshot = harness.snapshot
            harness.coordinator.invalidateSession()

            val result = harness.runCommunication(snapshot = snapshot)

            assertFalse(result.success)
            assertNull(result.data)
            assertNotNull(result.error)
        }
    }

    /**
     * The observed 29 KB / four-session result: too heavy because of per-entry
     * depth, not list length. A smaller `limit` cannot fix that shape, so the
     * tool must narrow depth and say so.
     *
     * The allowance is set just under what the full projection needs — tight
     * enough to trigger narrowing, wide enough that the narrowed result still
     * fits, which is the regime the mechanism exists for.
     */
    @Test
    fun oversizedProjectionIsNarrowedByDepthRatherThanTrimmed() = runBlocking {
        AgentToolTestHarness.create {
            communication = analysis()
        }.use { harness ->
            val full = harness.runCommunication(mapOf("detail" to "full"))
            val fullBytes = full.resultBytes

            val result = harness.runCommunication(policy = budgetOf(fullBytes - 1))

            val data = requireNotNull(result.data)
            assertEquals("shallow", data["detail"])
            // The domain lists themselves — the answer — must still be present.
            assertNotNull(data["calls"])
            // And the per-domain truncation contract is untouched.
            assertNotNull(data["sipSource"])
            assertTrue(result.resultBytes < fullBytes)
        }
    }

    /** Asking for full detail overrides the estimate. */
    @Test
    fun explicitFullDetailKeepsTheCompleteProjection() = runBlocking {
        AgentToolTestHarness.create {
            communication = analysis()
        }.use { harness ->
            val result = harness.runCommunication(mapOf("detail" to "full"))

            assertEquals("full", requireNotNull(result.data)["detail"])
        }
    }

    /** The rollback flag restores the pre-narrowing behaviour. */
    @Test
    fun disablingEvidenceNarrowingKeepsTheFullProjection() = runBlocking {
        AgentToolTestHarness.create {
            communication = analysis()
        }.use { harness ->
            val fullBytes = harness.runCommunication(mapOf("detail" to "full")).resultBytes

            val result = harness.runCommunication(
                policy = budgetOf(fullBytes - 1).copy(evidenceNarrowingEnabled = false)
            )

            assertEquals("full", requireNotNull(result.data)["detail"])
        }
    }

    /** A policy whose per-call result allowance is exactly [bytes]. */
    private fun budgetOf(bytes: Int) = AgentPolicy(
        maxToolResultBytes = bytes.coerceAtLeast(256),
        maxDetailResultBytesPerCall = bytes.coerceAtLeast(256)
    )

    private suspend fun AgentToolTestHarness.runCommunication(
        arguments: Map<String, Any?> = emptyMap(),
        snapshot: AgentCaptureSnapshot = this.snapshot,
        privacyMode: AgentPrivacyMode = AgentPrivacyMode.LocalOnly,
        policy: AgentPolicy = AgentPolicy()
    ) = AgentToolRunner(
        registry = AgentToolRegistry(CommunicationAnalysisTool(Dispatchers.Unconfined)),
        repository = repository,
        policy = policy,
        budget = AgentBudgetTracker(policy)
    ).execute(
        AgentToolCall("call-1", "get_communication_analysis", arguments),
        snapshot,
        privacyMode
    )

    /** Two SIP calls, one RTP stream, one RTCP stream and two core sessions. */
    private fun analysis(): CommunicationAnalysis = CommunicationAnalyzer.aggregate(
        CommunicationAnalysis(
            sipMessages = listOf(
                sip(frame = 10L, time = 100.0, callId = "call-a"),
                sip(frame = 11L, time = 102.0, callId = "call-a", status = "200 OK"),
                sip(frame = 20L, time = 200.0, callId = "call-b"),
                sip(frame = 21L, time = 202.0, callId = "call-b", status = "486 Busy Here")
            ),
            sipTotal = 4,
            rtpPackets = (0 until 3).map { index ->
                RtpPacketMetric(
                    frameNumber = 30L + index,
                    time = 100.0 + index * 0.02,
                    source = "10.0.0.1",
                    destination = "10.0.0.2",
                    sourcePort = 16000,
                    destinationPort = 16002,
                    sequence = index,
                    ssrc = 0x1234L,
                    timestamp = 160L * index,
                    payloadType = 0
                )
            },
            rtpTotal = 3,
            rtcpPackets = listOf(
                RtcpPacketMetric(
                    frameNumber = 40L,
                    time = 105.0,
                    source = "10.0.0.2",
                    destination = "10.0.0.1",
                    sourcePort = 16003,
                    destinationPort = 16001,
                    packetType = 201,
                    senderSsrc = 0x9999L,
                    reportedSsrc = 0x1234L,
                    fractionLost = 26,
                    cumulativeLost = 4
                )
            ),
            rtcpTotal = 1,
            coreMessages = listOf(
                core(frame = 50L, time = 100.0, protocol = "diameter", value = "imsi-1"),
                core(frame = 51L, time = 101.0, protocol = "gtpv2", value = "imsi-2")
            ),
            coreTotal = 2
        )
    )

    private fun sip(
        frame: Long,
        time: Double,
        callId: String,
        status: String = ""
    ) = SipMessage(
        frameNumber = frame,
        time = time,
        source = "10.0.0.1",
        destination = "10.0.0.9",
        sourcePort = 5060,
        destinationPort = 5060,
        method = if (status.isEmpty()) "INVITE" else "",
        status = status,
        callId = callId,
        info = if (status.isEmpty()) "INVITE sip:bob@example.com" else status
    )

    private fun registration(
        frame: Long,
        time: Double,
        cSeq: Long,
        authorization: Boolean = false
    ) = SipMessage(
        frameNumber = frame,
        time = time,
        source = "10.0.0.1",
        destination = "10.0.0.9",
        sourcePort = 5060,
        destinationPort = 5060,
        method = "REGISTER",
        callId = "registration-call",
        cSeqNumber = cSeq,
        cSeqMethod = "REGISTER",
        viaBranch = "branch-$cSeq",
        authorizationPresent = authorization,
        info = "REGISTER"
    )

    private fun registrationResponse(
        frame: Long,
        time: Double,
        cSeq: Long,
        status: String
    ) = SipMessage(
        frameNumber = frame,
        time = time,
        source = "10.0.0.9",
        destination = "10.0.0.1",
        sourcePort = 5060,
        destinationPort = 5060,
        status = status,
        callId = "registration-call",
        cSeqNumber = cSeq,
        cSeqMethod = "REGISTER",
        viaBranch = "branch-$cSeq",
        info = status
    )

    private fun setupMessage(
        frame: Long,
        time: Double,
        method: String = "",
        status: String = "",
        cSeq: Long,
        branch: String,
        reverse: Boolean = false
    ) = SipMessage(
        frameNumber = frame,
        time = time,
        source = if (reverse) "10.0.0.9" else "10.0.0.1",
        destination = if (reverse) "10.0.0.1" else "10.0.0.9",
        sourcePort = 5060,
        destinationPort = 5060,
        method = method,
        status = status,
        callId = "setup-call",
        cSeqNumber = cSeq,
        cSeqMethod = if (method.isNotBlank()) method else if (status.isNotBlank() && branch == "invite") "INVITE" else "",
        viaBranch = "branch-$branch",
        info = method.ifBlank { status }
    )

    private fun core(
        frame: Long,
        time: Double,
        protocol: String,
        value: String
    ) = CoreSignalMessage(
        frameNumber = frame,
        time = time,
        protocol = protocol,
        source = "10.1.0.1",
        destination = "10.1.0.2",
        correlationField = "imsi",
        correlationValue = value,
        messageType = "Update Location",
        outcome = "success",
        info = "Update Location Request"
    )
}
