// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import java.io.File
import java.nio.file.Files
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentResponseDebugCaptureTest {
    @Test
    fun debugCaptureIsClosedByDefaultAndConsumesOneResponse() {
        withTempDirectory { directory ->
            val capture = AgentResponseDebugCapture(directory, buildDebug = true)

            assertTrue(capture.isAvailable)
            assertFalse(capture.isArmed)
            assertFalse(directory.exists())
            assertTrue(capture.armNextResponse())
            assertTrue(capture.isArmed)
            val session = capture.begin(
                AgentResponseDebugRequest(
                    runId = "run-1",
                    requestId = "run-1#request-1",
                    requestIdHash = "abc123"
                )
            )
            assertTrue(session != null)
            assertFalse(capture.isArmed)
            assertTrue(capture.begin(AgentResponseDebugRequest("run-1", "request-2")) == null)
            session!!.write("{\"choices\":[]}".toByteArray())
            val metadata = session.finish(
                httpStatus = 200,
                contentType = "application/json",
                processingLimitBytes = 512 * 1024L
            )

            assertTrue(metadata.captureComplete)
            assertTrue(File(directory, metadata.bodyFileName).isFile)
            assertFalse(File(directory, metadata.bodyFileName).name.endsWith(".part"))
            assertTrue(directory.listFiles()!!.any { it.name.endsWith(".metadata.json") })
            assertTrue(directory.listFiles()!!.any { it.name.endsWith(".summary.json") })
        }
    }

    @Test
    fun failureAndCancellationKeepPartFilesWithState() {
        withTempDirectory { directory ->
            val capture = AgentResponseDebugCapture(directory, buildDebug = true)
            assertTrue(capture.armNextResponse())
            val failed = capture.begin(AgentResponseDebugRequest("run-failure", "failure"))!!
            failed.write("provider error body".toByteArray())
            val failedMetadata = failed.finish(
                httpStatus = 502,
                contentType = "text/plain",
                processingLimitBytes = 64 * 1024L,
                processingFailure = "network"
            )
            assertFalse(failedMetadata.captureComplete)
            assertTrue(failedMetadata.bodyFileName.endsWith(".part"))

            assertTrue(capture.armNextResponse())
            val cancelled = capture.begin(AgentResponseDebugRequest("run-cancel", "cancel"))!!
            cancelled.write("partial".toByteArray())
            val cancelledMetadata = cancelled.finish(
                processingLimitBytes = 4 * 1024 * 1024L,
                processingFailure = "cancelled",
                cancelled = true
            )
            assertFalse(cancelledMetadata.captureComplete)
            assertTrue(cancelledMetadata.bodyFileName.endsWith(".part"))
        }
    }

    @Test
    fun oversizedDumpIsTruncatedAtEightMiBAndSummaryHasNoValues() {
        withTempDirectory { directory ->
            val capture = AgentResponseDebugCapture(directory, buildDebug = true)
            assertTrue(capture.armNextResponse())
            val session = capture.begin(
                AgentResponseDebugRequest(
                    runId = "sensitive-run",
                    requestId = "sensitive-request",
                    requestIdHash = "deadbeef"
                )
            )!!
            val chunk = ByteArray(64 * 1024) { 'x'.code.toByte() }
            repeat((AgentResponseDebugCapture.MAX_SINGLE_BYTES / chunk.size).toInt()) {
                session.write(chunk)
            }
            session.write("overflow".toByteArray())
            val metadata = session.finish(
                httpStatus = 200,
                contentType = "application/json",
                processingLimitBytes = 512 * 1024L,
                processingFailure = "response_too_large"
            )

            assertFalse(metadata.captureComplete)
            assertEquals("size_limit", metadata.dumpTruncatedReason)
            assertEquals(
                AgentResponseDebugCapture.MAX_SINGLE_BYTES,
                File(directory, metadata.bodyFileName).length()
            )
            val metadataJson = JSONObject(
                File(directory, metadata.metadataFileName).readText()
            )
            val summaryJson = JSONObject(File(directory, metadata.summaryFileName).readText())
            assertFalse(metadataJson.toString().contains("Authorization"))
            assertFalse(metadataJson.toString().contains("sensitive-run"))
            assertFalse(metadataJson.toString().contains("sensitive-request"))
            assertFalse(summaryJson.toString().contains("xxxxxxxx"))
            assertTrue(summaryJson.getBoolean("structureParseFailed"))
        }
    }

    @Test
    fun releaseConstructionCannotArmOrCreateAResidualDirectory() {
        withTempDirectory { directory ->
            val capture = AgentResponseDebugCapture(directory, buildDebug = false)

            assertFalse(capture.isAvailable)
            assertFalse(capture.armNextResponse())
            assertFalse(capture.isArmed)
            assertFalse(directory.exists())
        }
    }

    @Test
    fun continuousDebugCaptureRecordsEveryResponseAndKeepsOnlyTheNewestFour() {
        withTempDirectory { directory ->
            var continuous = true
            var now = System.currentTimeMillis()
            val capture = AgentResponseDebugCapture(
                directory = directory,
                buildDebug = true,
                continuousEnabledProvider = { continuous },
                clock = { now }
            )

            repeat(AgentResponseDebugCapture.MAX_DUMPS + 2) { index ->
                val session = capture.begin(
                    AgentResponseDebugRequest("run-$index", "request-$index")
                )
                assertTrue(session != null)
                session!!.write("{\"index\":$index}".toByteArray())
                session.finish(processingLimitBytes = 64 * 1024L)
                now += 1L
            }

            assertTrue(
                directory.listFiles().orEmpty().count { it.name.endsWith(".metadata.json") } <=
                    AgentResponseDebugCapture.MAX_DUMPS
            )
            continuous = false
            assertTrue(capture.begin(AgentResponseDebugRequest("run-off", "request-off")) == null)
        }
    }

    @Test
    fun releaseConstructionCannotEnableContinuousCapture() {
        withTempDirectory { directory ->
            val capture = AgentResponseDebugCapture(
                directory = directory,
                buildDebug = false,
                continuousEnabledProvider = { true }
            )

            assertTrue(capture.begin(AgentResponseDebugRequest("run", "request")) == null)
            assertFalse(directory.exists())
        }
    }

    @Test
    fun ttlCountAndCapacityCleanupAreBounded() {
        withTempDirectory { directory ->
            var now = System.currentTimeMillis()
            val capture = AgentResponseDebugCapture(directory, buildDebug = true) { now }
            repeat(AgentResponseDebugCapture.MAX_DUMPS + 1) { index ->
                assertTrue(capture.armNextResponse())
                val session = capture.begin(
                    AgentResponseDebugRequest("run-$index", "request-$index")
                )!!
                session.write(ByteArray(AgentResponseDebugCapture.MAX_SINGLE_BYTES.toInt()))
                session.finish(processingLimitBytes = 4 * 1024 * 1024L)
                now += 1L
            }

            capture.cleanup(nowMillis = now)
            val files = directory.listFiles().orEmpty()
            val metadataFiles = files.count { it.name.endsWith(".metadata.json") }
            assertTrue(metadataFiles <= AgentResponseDebugCapture.MAX_DUMPS)
            assertTrue(capture.totalBytes() <= AgentResponseDebugCapture.MAX_TOTAL_BYTES)

            capture.cleanup(
                nowMillis = System.currentTimeMillis() +
                    AgentResponseDebugCapture.RETENTION_MILLIS + 1_000L
            )
            assertEquals(0L, capture.totalBytes())
        }
    }

    private fun withTempDirectory(block: (java.io.File) -> Unit) {
        val root = Files.createTempDirectory("agent-response-capture").toFile()
        val directory = File(root, "agent_response_dumps")
        try {
            block(directory)
        } finally {
            root.deleteRecursively()
        }
    }
}
