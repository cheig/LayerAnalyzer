// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.agent.AgentBudgetTracker
import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolCall
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONObject

class AgentToolRunnerTest {
    @Test
    fun heavyNativeTimeoutStaysWithinThePerStepCeiling() {
        assertEquals(
            120_000L,
            calculateAgentToolTimeoutMillis(
                toolName = "get_communication_analysis",
                frameCount = 13_702,
                defaultTimeoutMillis = 30_000L,
                maxToolTimeoutMillis = 120_000L
            )
        )
        assertEquals(
            30_000L,
            calculateAgentToolTimeoutMillis(
                toolName = "get_packet_fields",
                frameCount = 13_702,
                defaultTimeoutMillis = 30_000L,
                maxToolTimeoutMillis = 120_000L
            )
        )
    }

    @Test
    fun unknownToolIsRejectedWithoutReflectionOrFuzzyMatching() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val runner = runner(harness, FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("ok" to true))
            })

            val result = runner.execute(
                AgentToolCall("call-1", "com.example.layanalyzer.NativeEngine"),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
            assertEquals("unknown_tool", result.error?.details?.get("reason"))
            // A near-miss name must not resolve either.
            val nearMiss = runner.execute(
                AgentToolCall("call-2", "get_capture_overview "),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )
            assertFalse(nearMiss.success)
        }
    }

    @Test
    fun duplicateToolNamesAreRejectedAtConstruction() {
        val first = FakeTool("get_statistics") { _, context -> context.success(emptyMap()) }
        val second = FakeTool("get_statistics") { _, context -> context.success(emptyMap()) }

        val failure = runCatching { AgentToolRegistry(listOf(first, second)) }.exceptionOrNull()

        assertTrue(failure is IllegalArgumentException)
        assertTrue(failure?.message?.contains("get_statistics") == true)
    }

    @Test
    fun registryRejectsNonSnakeCaseToolNames() {
        val failure = runCatching {
            AgentToolRegistry(listOf(FakeTool("GetStatistics") { _, c -> c.success(emptyMap()) }))
        }.exceptionOrNull()

        assertTrue(failure is IllegalArgumentException)
    }

    @Test
    fun extraArgumentIsRejectedBeforeToolRuns() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_statistics") { _, context -> context.success(mapOf("ok" to true)) }
            val runner = runner(harness, tool)

            val result = runner.execute(
                AgentToolCall("call-1", "get_statistics", mapOf("outputPath" to "/sdcard/leak.json")),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
            assertEquals("arguments.outputPath", result.error?.details?.get("path"))
            assertEquals(0, tool.executionCount)
        }
    }

    @Test
    fun invalidArgumentsDoNotConsumeAStep() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tracker = AgentBudgetTracker(AgentPolicy())
            val runner = runner(
                harness,
                FakeTool("get_statistics") { _, context -> context.success(mapOf("ok" to true)) },
                tracker = tracker
            )

            runner.execute(
                AgentToolCall("call-1", "get_statistics", mapOf("nope" to 1)),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertEquals(0, tracker.usage().steps)
        }
    }

    @Test
    fun orchestrationToolPassesTheRunnerWithoutConsumingEvidenceStep() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val policy = AgentPolicy(maxSteps = 1)
            val tracker = AgentBudgetTracker(policy)
            val runner = runner(
                harness,
                DeclareAnalysisPlanTool(),
                policy = policy,
                tracker = tracker
            )

            val result = runner.execute(
                AgentToolCall(
                    "plan-1",
                    DeclareAnalysisPlanTool.NAME,
                    mapOf(
                        "goal" to "Assess capture health",
                        "steps" to listOf(
                            mapOf("tool" to "get_capture_overview", "purpose" to "Read baseline")
                        )
                    )
                ),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertTrue(result.success)
            assertEquals(0, tracker.usage().steps)
            assertTrue(tracker.usage().resultBytes > 0L)
        }
    }

    @Test
    fun anOversizedDetailRequestIsGrantedPartiallyInsteadOfRejected() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool(
                name = "get_packet_fields",
                schema = FakeTool.FRAMES_SCHEMA,
                frameArgument = "frames"
            ) { _, context ->
                context.success(
                    mapOf(
                        "frames" to requireNotNull(context.grantedDetailFrames).sorted(),
                        "omittedFrames" to context.omittedDetailFrames,
                        "remainingFrameQuota" to context.remainingDetailFrameQuota
                    ),
                    returnedCount = context.grantedDetailFrames!!.size.toLong(),
                    totalCount = 20L,
                    truncated = context.omittedDetailFrames.isNotEmpty()
                )
            }
            val runner = runner(harness, tool, policy = AgentPolicy(maxDetailFramesPerCall = 8))

            val result = runner.execute(
                AgentToolCall("call-1", "get_packet_fields", mapOf("frames" to (1..20).toList())),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertTrue(result.success)
            assertTrue(result.truncated)
            @Suppress("UNCHECKED_CAST")
            val data = requireNotNull(result.data)
            assertEquals((1L..8L).toList(), data["frames"])
            assertEquals((9L..20L).toList(), data["omittedFrames"])
            // The tool ran with the granted prefix rather than being rejected.
            assertEquals(1, tool.executionCount)
        }
    }

    @Test
    fun detailFrameSessionLimitCannotBeBypassedBySplittingCalls() = runBlocking {
        AgentToolTestHarness.create(frameCount = 200).use { harness ->
            val tool = FakeTool(
                name = "get_packet_fields",
                schema = FakeTool.FRAMES_SCHEMA,
                frameArgument = "frames"
            ) { _, context ->
                val granted = context.grantedDetailFrames.orEmpty()
                context.success(
                    mapOf("grantedCount" to granted.size),
                    returnedCount = granted.size.toLong(),
                    totalCount = 4L,
                    truncated = context.omittedDetailFrames.isNotEmpty()
                )
            }
            val policy = AgentPolicy(
                maxSteps = 20,
                maxDetailFramesPerCall = 4,
                maxDetailFramesPerSession = 8
            )
            val runner = runner(harness, tool, policy = policy)

            val outcomes = (0 until 4).map { index ->
                val start = index * 4 + 1
                runner.execute(
                    AgentToolCall("call-$index", "get_packet_fields", mapOf("frames" to (start until start + 4).toList())),
                    harness.snapshot,
                    AgentPrivacyMode.RedactedMetadata
                )
            }

            // Two full calls fit the session; the third is answered without a
            // single granted frame and without invoking the tool.
            assertTrue(outcomes[0].success)
            assertTrue(outcomes[1].success)
            assertTrue(outcomes[2].success)
            assertEquals(2, tool.executionCount)

            val emptyAccount = requireNotNull(outcomes[2].data)
            assertEquals(true, emptyAccount["detailBudgetExhausted"])
            assertEquals(true, emptyAccount["omittedByBudget"])
            assertEquals(0, emptyAccount["remainingFrameQuota"])
            assertEquals((9L..12L).toList(), emptyAccount["omittedFrames"])
            assertTrue(outcomes[2].truncated)
        }
    }

    @Test
    fun rereadingTheSameFrameDoesNotPayTwice() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool(
                name = "get_packet_fields",
                schema = FakeTool.FRAMES_SCHEMA,
                frameArgument = "frames"
            ) { _, context -> context.success(mapOf("ok" to true)) }
            val runner = runner(
                harness,
                tool,
                policy = AgentPolicy(maxDetailFramesPerCall = 4, maxDetailFramesPerSession = 4)
            )

            repeat(3) { index ->
                val result = runner.execute(
                    AgentToolCall("call-$index", "get_packet_fields", mapOf("frames" to listOf(1, 2, 3))),
                    harness.snapshot,
                    AgentPrivacyMode.RedactedMetadata
                )
                assertTrue(result.success)
            }

            assertEquals(3, tool.executionCount)
        }
    }

    @Test
    fun stepLimitStopsFurtherCalls() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_statistics") { _, context -> context.success(mapOf("ok" to true)) }
            val runner = runner(harness, tool, policy = AgentPolicy(maxSteps = 2))

            val results = (0 until 3).map { index ->
                runner.execute(
                    AgentToolCall("call-$index", "get_statistics"),
                    harness.snapshot,
                    AgentPrivacyMode.RedactedMetadata
                )
            }

            assertTrue(results[0].success)
            assertTrue(results[1].success)
            assertFalse(results[2].success)
            assertEquals(AgentErrorCode.MAX_STEPS_REACHED, results[2].error?.code)
            assertEquals(2, tool.executionCount)
        }
    }

    @Test
    fun toolTimeoutMapsToToolTimeout() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val runner = runner(
                harness,
                FakeTool("get_statistics", timeoutMillis = 40L) { _, _ ->
                    delay(10_000L)
                    error("unreachable")
                }
            )

            val result = runner.execute(
                AgentToolCall("call-1", "get_statistics"),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertFalse(result.success)
            assertEquals(AgentErrorCode.TOOL_TIMEOUT, result.error?.code)
            assertTrue(result.error?.retryable == true)
        }
    }

    @Test
    fun cancellationPropagatesInsteadOfBecomingInternalError() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val entered = CompletableDeferred<Unit>()
            val runner = runner(
                harness,
                FakeTool("get_statistics", timeoutMillis = 60_000L) { _, _ ->
                    entered.complete(Unit)
                    awaitCancellation()
                }
            )

            val job = async(Dispatchers.Default) {
                runner.execute(
                    AgentToolCall("call-1", "get_statistics"),
                    harness.snapshot,
                    AgentPrivacyMode.RedactedMetadata
                )
            }
            entered.await()
            job.cancel()

            val failure = runCatching { job.await() }.exceptionOrNull()
            assertTrue(failure is CancellationException)
        }
    }

    @Test
    fun toolThrowingIsMappedToStructuredInternalErrorWithoutLeakingMessage() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val runner = runner(
                harness,
                FakeTool("get_statistics") { _, _ ->
                    error("/data/user/0/com.layeranalyzer.android/files/secret.pcap missing")
                }
            )

            val result = runner.execute(
                AgentToolCall("call-1", "get_statistics"),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INTERNAL_ERROR, result.error?.code)
            assertFalse(result.error?.userMessage?.contains("secret.pcap") == true)
            assertFalse(result.error?.details?.values?.any { it.toString().contains("/data/") } == true)
        }
    }

    @Test
    fun payloadToolIsBlockedInDefaultPrivacyMode() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool(
                name = "follow_stream_text",
                sensitivity = AgentDataSensitivity.Payload
            ) { _, context -> context.success(mapOf("text" to "secret")) }
            val runner = runner(harness, tool)

            val result = runner.execute(
                AgentToolCall("call-1", "follow_stream_text"),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertFalse(result.success)
            assertEquals(AgentErrorCode.PRIVACY_BLOCKED, result.error?.code)
            assertEquals(0, tool.executionCount)
            assertNull(result.data)
        }
    }

    @Test
    fun payloadToolRunsOnlyWhenPolicyAndModeBothAllowIt() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool(
                name = "follow_stream_text",
                sensitivity = AgentDataSensitivity.Payload
            ) { _, context -> context.success(mapOf("text" to "body")) }
            val runner = runner(harness, tool, policy = AgentPolicy(allowPayload = true))

            val blocked = runner.execute(
                AgentToolCall("call-1", "follow_stream_text"),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )
            assertEquals(AgentErrorCode.PRIVACY_BLOCKED, blocked.error?.code)

            val allowed = runner.execute(
                AgentToolCall("call-2", "follow_stream_text"),
                harness.snapshot,
                AgentPrivacyMode.SelectedPayload
            )
            assertTrue(allowed.success)
        }
    }

    @Test
    fun credentialToolIsNeverAllowed() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val runner = runner(
                harness,
                FakeTool("read_authorization", sensitivity = AgentDataSensitivity.Credential) { _, context ->
                    context.success(mapOf("token" to "secret"))
                },
                policy = AgentPolicy(allowPayload = true)
            )

            AgentPrivacyMode.entries.forEach { mode ->
                val result = runner.execute(
                    AgentToolCall("call-${mode.name}", "read_authorization"),
                    harness.snapshot,
                    mode
                )
                assertEquals(AgentErrorCode.PRIVACY_BLOCKED, result.error?.code)
            }
        }
    }

    @Test
    fun oversizedResultIsTruncatedToValidJsonWithAccurateFlag() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val runner = runner(
                harness,
                FakeTool("query_packet_summaries") { _, context ->
                    val rows = (1..5_000).map { index ->
                        mapOf(
                            "frame" to index,
                            "info" to "A".repeat(200)
                        )
                    }
                    context.success(
                        data = mapOf("packets" to rows),
                        returnedCount = rows.size.toLong(),
                        totalCount = rows.size.toLong()
                    )
                }
            )

            val result = runner.execute(
                AgentToolCall("call-1", "query_packet_summaries"),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertTrue(result.success)
            assertTrue(result.truncated)
            assertTrue(result.provenance.truncated)

            val encoded = AgentResultTruncator.encode(checkNotNull(result.data))
            assertTrue(encoded.toByteArray(Charsets.UTF_8).size <= AgentPolicy().maxToolResultBytes)
            // Must still parse: a byte-level cut would throw here.
            val parsed = JSONObject(encoded)
            assertTrue(parsed.getBoolean("packetsTruncated"))
            assertEquals(5_000, parsed.getInt("packetsTotal"))
            assertTrue(parsed.getJSONArray("packets").length() < 5_000)
        }
    }

    @Test
    fun smallResultIsNotMarkedTruncated() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val runner = runner(
                harness,
                FakeTool("get_statistics") { _, context ->
                    context.success(
                        data = mapOf("packetCount" to 10, "protocols" to listOf("tcp", "udp")),
                        returnedCount = 2L,
                        totalCount = 2L
                    )
                }
            )

            val result = runner.execute(
                AgentToolCall("call-1", "get_statistics"),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertTrue(result.success)
            assertFalse(result.truncated)
            assertFalse(result.provenance.truncated)
            assertEquals(2L, result.returnedCount)
        }
    }

    @Test
    fun everyResultCarriesCompleteProvenance() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val runner = runner(
                harness,
                FakeTool("get_statistics", version = "3") { _, context ->
                    context.success(mapOf("ok" to true), returnedCount = 1L, totalCount = 7L)
                }
            )

            val result = runner.execute(
                AgentToolCall("call-1", "get_statistics", mapOf("filter" to "tcp")),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val provenance = result.provenance
            assertEquals(harness.snapshot.captureFingerprint, provenance.captureFingerprint)
            assertEquals(harness.snapshot.scope, provenance.scope)
            assertEquals("get_statistics", provenance.toolName)
            assertEquals("3", provenance.toolVersion)
            assertTrue(provenance.normalizedArgumentsHash.isNotBlank())
            assertTrue(provenance.generatedAtMillis > 0L)
            assertEquals(1L, provenance.returnedCount)
            assertEquals(7L, provenance.totalCount)
            assertFalse(provenance.truncated)
            assertNotNull(provenance.localSessionReference)
        }
    }

    @Test
    fun localSessionReferenceIsHashedAndStrippedBeforeReachingModel() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val runner = runner(
                harness,
                FakeTool("get_statistics") { _, context -> context.success(mapOf("ok" to true)) }
            )

            val result = runner.execute(
                AgentToolCall("call-1", "get_statistics"),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val reference = checkNotNull(result.provenance.localSessionReference)
            // A fixed-width hex digest, not the handle or any decimal form of it.
            assertTrue(reference.matches(Regex("^[0-9a-f]{24}$")))
            assertNotEquals(harness.snapshot.sessionHandle.toString(), reference)

            // The same session hashes stably; a different session must not.
            val repeat = runner.execute(
                AgentToolCall("call-2", "get_statistics"),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )
            assertEquals(reference, repeat.provenance.localSessionReference)

            val message = com.example.layanalyzer.model.AgentModelMessage.fromToolResult(result)
            assertNull(message.toolResult?.provenance?.localSessionReference)
            assertTrue(message.untrustedCaptureData)
        }
    }

    @Test
    fun argumentHashIsStableAcrossKeyOrderInsideTheRunner() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val runner = runner(
                harness,
                FakeTool("get_statistics") { _, context -> context.success(mapOf("ok" to true)) }
            )

            val first = runner.execute(
                AgentToolCall("call-1", "get_statistics", linkedMapOf("filter" to "tcp", "limit" to 5)),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )
            val second = runner.execute(
                AgentToolCall("call-2", "get_statistics", linkedMapOf("limit" to 5, "filter" to "tcp")),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )
            val third = runner.execute(
                AgentToolCall("call-3", "get_statistics", linkedMapOf("limit" to 6, "filter" to "tcp")),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertEquals(
                first.provenance.normalizedArgumentsHash,
                second.provenance.normalizedArgumentsHash
            )
            assertNotEquals(
                first.provenance.normalizedArgumentsHash,
                third.provenance.normalizedArgumentsHash
            )
        }
    }

    @Test
    fun sessionChangeAfterExecutionDiscardsResult() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val runner = runner(
                harness,
                FakeTool("get_statistics") { _, context ->
                    // Simulate the user closing the capture mid-read.
                    harness.coordinator.invalidateSession()
                    context.success(mapOf("packetCount" to 10))
                }
            )

            val result = runner.execute(
                AgentToolCall("call-1", "get_statistics"),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertFalse(result.success)
            assertTrue(
                result.error?.code == AgentErrorCode.SESSION_CHANGED ||
                    result.error?.code == AgentErrorCode.NO_CAPTURE
            )
            assertNull(result.data)
        }
    }

    @Test
    fun auditEntriesRecordMetadataWithoutRawArguments() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val entries = mutableListOf<AgentToolAuditEntry>()
            val runner = runner(
                harness,
                FakeTool("get_statistics") { _, context ->
                    context.success(mapOf("ok" to true), returnedCount = 1L, totalCount = 4L)
                },
                auditLog = AgentToolAuditLog { entries += it }
            )

            runner.execute(
                AgentToolCall("call-1", "get_statistics", mapOf("filter" to "sip.Call-ID == \"secret\"")),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertEquals(1, entries.size)
            val entry = entries.single()
            assertEquals("get_statistics", entry.toolName)
            assertTrue(entry.success)
            assertEquals(1L, entry.returnedCount)
            assertEquals(4L, entry.totalCount)
            assertTrue(entry.resultBytes > 0)
            assertTrue(entry.normalizedArgumentsHash.isNotBlank())
            assertFalse(entry.toString().contains("secret"))
        }
    }

    @Test
    fun definitionsExposeNoImplementationDetails() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val runner = runner(
                harness,
                FakeTool("get_statistics") { _, context -> context.success(mapOf("ok" to true)) }
            )

            val rendered = runner.toolDefinitions().joinToString { definition ->
                "${definition.name}|${definition.description}|${definition.inputSchema}"
            }

            assertFalse(rendered.contains("com.example.layanalyzer"))
            assertFalse(rendered.contains("NativeEngine"))
            assertFalse(rendered.contains("/data/"))
            assertFalse(rendered.contains("sessionPtr"))
        }
    }

    @Test
    fun delegateInvestigationTruncatesSupportedOverLengthGoals() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val received = mutableListOf<String>()
            val entries = mutableListOf<AgentToolAuditEntry>()
            val runner = runner(
                harness,
                DelegateInvestigationTool(),
                auditLog = AgentToolAuditLog(entries::add)
            )
            runner.bindInvestigationDelegate { goal, _ ->
                received += goal
                mapOf("summary" to "ok", "findings" to emptyList<Any>())
            }

            val results = listOf(2_000, 2_049, 8_000).mapIndexed { index, length ->
                runner.execute(
                    AgentToolCall(
                        "delegate-${index + 1}",
                        DelegateInvestigationTool.NAME,
                        mapOf("goal" to "x".repeat(length))
                    ),
                    harness.snapshot,
                    AgentPrivacyMode.RedactedMetadata
                )
            }

            assertTrue(results.all { it.success })
            assertEquals(listOf(1_000, 1_000, 1_000), received.map(String::length))
            assertEquals(listOf(2_000L, 2_049L, 8_000L), results.map {
                ((it.data?.get("goalNormalization") as Map<*, *>)["originalLength"] as Number).toLong()
            })
            assertTrue(results.all {
                (it.data?.get("goalNormalization") as Map<*, *>)["normalizedLength"] == 1_000
            })
            assertEquals(3, entries.size)
            assertTrue(entries.all { it.normalizationCount == 1 })
            assertTrue(entries.all { it.normalizationPaths == listOf("arguments.goal") })
        }
    }

    private fun runner(
        harness: AgentToolTestHarness,
        vararg tools: AgentTool,
        policy: AgentPolicy = AgentPolicy(),
        tracker: AgentBudgetTracker = AgentBudgetTracker(policy),
        auditLog: AgentToolAuditLog? = null
    ) = AgentToolRunner(
        registry = AgentToolRegistry(tools.toList()),
        repository = harness.repository,
        policy = policy,
        budget = tracker,
        auditLog = auditLog
    )
}
