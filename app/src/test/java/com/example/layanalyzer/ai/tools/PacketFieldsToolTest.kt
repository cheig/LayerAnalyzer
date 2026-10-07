package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.agent.AgentBudgetTracker
import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.ProtocolNode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketFieldsToolTest {

    @Test
    fun requestedFieldsAreProjectedPerFrame() = runBlocking {
        AgentToolTestHarness.create(frameCount = 10) {
            details = mapOf(
                1L to sipFrame("INVITE"),
                2L to sipFrame("ACK")
            )
        }.use { harness ->
            val result = harness.runFields(
                mapOf("frames" to listOf(1, 2), "fields" to listOf("sip.Method"))
            )

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val frames = data["frames"] as List<Map<String, Any?>>
            assertEquals(2, frames.size)
            assertEquals(2, data["returned"])
            assertEquals(2, data["total"])

            @Suppress("UNCHECKED_CAST")
            val firstFields = frames[0]["fields"] as Map<String, List<Map<String, Any?>>>
            assertEquals("INVITE", firstFields["sip.Method"]?.single()?.get("displayValue"))
            assertEquals(true, frames[0]["detailAvailable"])
        }
    }

    @Test
    fun aMissingFieldAndAnUnreadableFrameAreDistinguishable() = runBlocking {
        AgentToolTestHarness.create(frameCount = 10) {
            // Frame 1 dissects but has no rtp.ssrc; frame 2 fails to dissect.
            details = mapOf(1L to sipFrame("INVITE"))
        }.use { harness ->
            val result = harness.runFields(
                mapOf("frames" to listOf(1, 2), "fields" to listOf("rtp.ssrc"))
            )

            @Suppress("UNCHECKED_CAST")
            val frames = requireNotNull(result.data)["frames"] as List<Map<String, Any?>>

            val readable = frames.single { it["frameNumber"] == 1L }
            assertEquals(true, readable["detailAvailable"])
            assertEquals(listOf("rtp.ssrc"), readable["missingFields"])

            val unreadable = frames.single { it["frameNumber"] == 2L }
            assertEquals(false, unreadable["detailAvailable"])
            assertEquals(listOf("rtp.ssrc"), unreadable["missingFields"])

            // The frame that failed is still present, so the model can tell the
            // two situations apart instead of seeing a silently shorter list.
            assertEquals(2, frames.size)
        }
    }

    @Test
    fun anOutOfRangeFrameIsReportedWithoutFailingTheWholeCall() = runBlocking {
        AgentToolTestHarness.create(frameCount = 5) {
            details = mapOf(1L to sipFrame("INVITE"))
        }.use { harness ->
            val result = harness.runFields(
                mapOf("frames" to listOf(1, 9_999), "fields" to listOf("sip.Method"))
            )

            assertTrue(result.success)
            @Suppress("UNCHECKED_CAST")
            val frames = requireNotNull(result.data)["frames"] as List<Map<String, Any?>>
            assertEquals(true, frames.single { it["frameNumber"] == 1L }["detailAvailable"])
            assertEquals(false, frames.single { it["frameNumber"] == 9_999L }["detailAvailable"])
        }
    }

    @Test
    fun repeatedFieldsAreAllReturned() = runBlocking {
        AgentToolTestHarness.create(frameCount = 5) {
            details = mapOf(
                1L to ProtocolNode(
                    label = "SIP",
                    children = listOf(
                        field("sip.Via", "SIP/2.0/UDP proxy1"),
                        field("sip.Via", "SIP/2.0/UDP proxy2"),
                        field("sip.Via", "SIP/2.0/UDP proxy3")
                    )
                )
            )
        }.use { harness ->
            val result = harness.runFields(
                mapOf("frames" to listOf(1), "fields" to listOf("sip.Via"))
            )

            @Suppress("UNCHECKED_CAST")
            val frames = requireNotNull(result.data)["frames"] as List<Map<String, Any?>>
            @Suppress("UNCHECKED_CAST")
            val occurrences = (frames.single()["fields"] as Map<String, List<*>>)["sip.Via"]
            assertEquals(3, occurrences?.size)
        }
    }

    @Test
    fun aFieldNameIsNeverTreatedAsADisplayFilter() = runBlocking {
        AgentToolTestHarness.create(frameCount = 5) {
            details = mapOf(1L to sipFrame("INVITE"))
        }.use { harness ->
            listOf(
                "sip.Method == INVITE",
                "frame.number > 1",
                "ip.src == \"10.0.0.1\"",
                "sip.Method; rm -rf /",
                "../../etc/passwd"
            ).forEach { name ->
                val result = harness.runFields(
                    mapOf("frames" to listOf(1), "fields" to listOf(name))
                )
                assertFalse(name, result.success)
                assertEquals(name, AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
            }

            // The rejected name is not echoed back into the transcript.
            val rejected = harness.runFields(
                mapOf("frames" to listOf(1), "fields" to listOf("sip.Method == INVITE"))
            )
            assertFalse(rejected.error?.details?.values?.any {
                it.toString().contains("INVITE")
            } ?: false)
        }
    }

    @Test
    fun credentialFieldsAreReturnedAsExistenceMetadata() = runBlocking {
        val secret = "Digest username=\"alice\", response=\"c0ffee\""
        AgentToolTestHarness.create(frameCount = 5) {
            details = mapOf(
                1L to ProtocolNode(
                    label = "SIP",
                    children = listOf(field("sip.Authorization", secret))
                )
            )
        }.use { harness ->
            val result = harness.runFields(
                mapOf("frames" to listOf(1), "fields" to listOf("sip.Authorization"))
            )

            val encoded = AgentResultTruncator.encode(requireNotNull(result.data))
            assertTrue(encoded.contains("\"credential\":true"))
            assertFalse(encoded.contains("alice"))
            assertFalse(encoded.contains("c0ffee"))
        }
    }

    @Test
    fun payloadFieldsAreReturnedAsPresenceMetadataEvenInLocalOnlyMode() = runBlocking {
        val payload = "do not send this body"
        AgentToolTestHarness.create(frameCount = 1) {
            details = mapOf(
                1L to ProtocolNode(
                    label = "TCP",
                    children = listOf(field("tcp.payload", payload))
                )
            )
        }.use { harness ->
            val result = AgentToolRunner(
                registry = AgentToolRegistry(PacketFieldsTool(Dispatchers.Unconfined)),
                repository = harness.repository
            ).execute(
                AgentToolCall(
                    "payload-field",
                    "get_packet_fields",
                    mapOf("frames" to listOf(1), "fields" to listOf("tcp.payload"))
                ),
                harness.snapshot,
                AgentPrivacyMode.LocalOnly
            )

            assertTrue(result.success)
            val encoded = AgentResultTruncator.encode(requireNotNull(result.data))
            assertTrue(encoded.contains("\"payload\":true"))
            assertTrue(encoded.contains("\"present\":true"))
            assertFalse(encoded.contains(payload))
        }
    }

    @Test
    fun anOversizedCallReadsAGrantedPrefixAndOmitsTheRest() = runBlocking {
        AgentToolTestHarness.create(frameCount = 50).use { harness ->
            // The schema accepts up to 48 frames; the per-call budget grants 16.
            val result = harness.runFields(
                mapOf("frames" to (1..17).toList(), "fields" to listOf("sip.Method"))
            )

            assertTrue(result.success)
            assertTrue(result.truncated)
            val data = requireNotNull(result.data)
            assertEquals(16, data["returned"])
            assertEquals(17, data["total"])
            assertEquals((1L..16L).toList(), data["requestedFrames"]?.let { requested ->
                @Suppress("UNCHECKED_CAST")
                (requested as List<Long>).take(16)
            })
            assertEquals(listOf(17L), data["omittedFrames"])
            assertEquals(true, data["omittedByBudget"])
            assertEquals(true, data["omittedByPerCallLimit"])
            assertEquals(false, data["omittedBySessionQuota"])
            assertEquals(32, data["remainingFrameQuota"])

            @Suppress("UNCHECKED_CAST")
            val frames = data["frames"] as List<Map<String, Any?>>
            assertEquals(16, frames.size)
            assertEquals(1L, frames.first()["frameNumber"])
            assertEquals(16L, frames.last()["frameNumber"])
        }
    }

    @Test
    fun compactShortFieldRequestReceivesTheDynamicGrant() = runBlocking {
        AgentToolTestHarness.create(frameCount = 30).use { harness ->
            val result = harness.runFields(
                mapOf(
                    "frames" to (1..24).toList(),
                    "fields" to listOf("sip.Method"),
                    "includeDisplayValue" to false
                )
            )

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            assertEquals(24, data["requested"])
            assertEquals(24, data["granted"])
            assertEquals(24, data["returned"])
            assertEquals(emptyList<Long>(), data["omittedFrames"])
            assertEquals("dynamic_short_projection", data["detailGrantReason"])
            assertEquals(false, data["omittedByBudget"])
            assertEquals((1L..24L).toList(), harness.source.readDetailFrames)
        }
    }

    @Test
    fun detailResultIsStructurallyTrimmedWhenTheByteBudgetIsSmall() = runBlocking {
        AgentToolTestHarness.create(frameCount = 16) {
            details = (1L..16L).associateWith { frame ->
                ProtocolNode(
                    label = "SIP",
                    children = listOf(field("sip.Method", "VALUE-$frame-${"x".repeat(2_000)}"))
                )
            }
        }.use { harness ->
            val policy = AgentPolicy(
                maxToolResultBytes = 2_048,
                maxDetailResultBytesPerCall = 2_048,
                maxDetailResultBytesPerSession = 2_048L,
                maxTotalResultBytes = 8_192L
            )
            val runner = AgentToolRunner(
                registry = AgentToolRegistry(PacketFieldsTool(Dispatchers.Unconfined)),
                repository = harness.repository,
                policy = policy,
                budget = AgentBudgetTracker(policy)
            )
            val result = runner.execute(
                AgentToolCall(
                    "small-byte-budget",
                    "get_packet_fields",
                    mapOf("frames" to (1..16).toList(), "fields" to listOf("sip.Method"))
                ),
                harness.snapshot,
                AgentPrivacyMode.LocalOnly
            )

            assertTrue(result.success)
            assertTrue(result.truncated)
            assertTrue(result.resultBytes <= 2_048)
            val data = requireNotNull(result.data)
            assertEquals(true, data["payloadTruncated"])
            @Suppress("UNCHECKED_CAST")
            val frames = data["frames"] as List<Map<String, Any?>>
            assertEquals(frames.size, data["returned"])
            assertTrue(frames.size < 16)
            assertEquals(frames.size.toLong(), result.returnedCount)
            assertEquals(16L, result.totalCount)
            assertTrue(data.containsKey("payloadOmittedFrames"))
        }
    }

    @Test
    fun atMostThirtyTwoFieldsMayBeRequested() = runBlocking {
        AgentToolTestHarness.create(frameCount = 5).use { harness ->
            val fields = (1..33).map { "sip.Header$it" }
            val result = harness.runFields(mapOf("frames" to listOf(1), "fields" to fields))

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
        }
    }

    @Test
    fun theSessionDetailFrameBudgetAccumulatesAcrossCalls() = runBlocking {
        AgentToolTestHarness.create(frameCount = 100).use { harness ->
            val policy = AgentPolicy()
            val runner = AgentToolRunner(
                registry = AgentToolRegistry(PacketFieldsTool(Dispatchers.Unconfined)),
                repository = harness.repository,
                policy = policy,
                budget = AgentBudgetTracker(policy)
            )

            suspend fun read(frames: List<Int>, id: String) = runner.execute(
                AgentToolCall(id, "get_packet_fields", mapOf(
                    "frames" to frames,
                    "fields" to listOf("sip.Method")
                )),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            // 48 distinct frames is the session ceiling: three full calls fit.
            assertTrue(read((1..16).toList(), "c1").success)
            assertTrue(read((17..32).toList(), "c2").success)
            assertTrue(read((33..48).toList(), "c3").success)

            // The quota is spent: the next call is answered with an explicit
            // empty account rather than dissecting anything or failing.
            val overBudget = read((49..64).toList(), "c4")
            assertTrue(overBudget.success)
            assertTrue(overBudget.truncated)
            val emptyAccount = requireNotNull(overBudget.data)
            assertEquals(true, emptyAccount["detailBudgetExhausted"])
            assertEquals(0, emptyAccount["returned"])
            assertEquals((49L..64L).toList(), emptyAccount["omittedFrames"])

            // Re-reading frames already charged stays allowed.
            val reread = read((1..16).toList(), "c5")
            assertTrue(reread.success)
            assertEquals(16, requireNotNull(reread.data)["returned"])
        }
    }

    @Test
    fun neitherPacketBytesNorTheFullTreeAppearInTheResult() = runBlocking {
        AgentToolTestHarness.create(frameCount = 5) {
            details = mapOf(
                1L to ProtocolNode(
                    label = "Frame",
                    children = listOf(
                        ProtocolNode(
                            label = "Ethernet",
                            filter = "eth",
                            children = listOf(field("eth.src", "00:11:22:33:44:55"))
                        ),
                        ProtocolNode(
                            label = "SIP",
                            filter = "sip",
                            children = listOf(field("sip.Method", "INVITE", start = 54, length = 6))
                        )
                    )
                )
            )
        }.use { harness ->
            val result = harness.runFields(
                mapOf("frames" to listOf(1), "fields" to listOf("sip.Method"))
            )
            val encoded = AgentResultTruncator.encode(requireNotNull(result.data))

            // Only the projected field: no siblings, no parents, no byte range.
            assertTrue(encoded.contains("sip.Method"))
            listOf("eth.src", "00:11:22", "Ethernet", "children", "\"start\"", "\"label\"")
                .forEach { forbidden -> assertFalse(forbidden, encoded.contains(forbidden)) }
        }
    }

    @Test
    fun framesAndFieldsAreBothRequired() = runBlocking {
        AgentToolTestHarness.create(frameCount = 5).use { harness ->
            assertFalse(harness.runFields(mapOf("fields" to listOf("sip.Method"))).success)
            assertFalse(harness.runFields(mapOf("frames" to listOf(1))).success)
            assertFalse(
                harness.runFields(
                    mapOf("frames" to emptyList<Int>(), "fields" to listOf("sip.Method"))
                ).success
            )
            assertFalse(
                harness.runFields(
                    mapOf("frames" to listOf(1), "fields" to emptyList<String>())
                ).success
            )
        }
    }

    @Test
    fun sessionChangeIsRejectedWithAStructuredError() = runBlocking {
        AgentToolTestHarness.create(frameCount = 5) {
            details = mapOf(1L to sipFrame("INVITE"))
        }.use { harness ->
            val snapshot = harness.snapshot
            harness.coordinator.invalidateSession()

            val result = harness.runFields(
                mapOf("frames" to listOf(1), "fields" to listOf("sip.Method")),
                snapshot = snapshot
            )

            assertFalse(result.success)
            assertNull(result.data)
            assertNotNull(result.error)
        }
    }

    private suspend fun AgentToolTestHarness.runFields(
        arguments: Map<String, Any?> = emptyMap(),
        snapshot: AgentCaptureSnapshot = this.snapshot
    ) = AgentToolRunner(
        registry = AgentToolRegistry(PacketFieldsTool(Dispatchers.Unconfined)),
        repository = repository
    ).execute(
        AgentToolCall("call-1", "get_packet_fields", arguments),
        snapshot,
        AgentPrivacyMode.RedactedMetadata
    )

    private fun sipFrame(method: String) = ProtocolNode(
        label = "SIP",
        children = listOf(field("sip.Method", method))
    )

    private fun field(
        name: String,
        value: String,
        start: Int = 0,
        length: Int = 0
    ) = ProtocolNode(
        label = "$name: $value",
        value = value,
        filter = name,
        filterValue = value,
        start = start,
        length = length
    )
}
