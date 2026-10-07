package com.example.layanalyzer.ai.client

import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/**
 * Contract tests for the bounded HTTP edge.
 *
 * The first version of these tests intentionally freezes the failure baseline:
 * the production transport used a 512 KiB line limit and leaked a body-read
 * timeout as a raw SocketTimeoutException.  The expectations are updated with
 * the new error contract as the transport fix is applied.
 */
class AgentHttpTransportTest {
    @Test
    fun responseExactlyAtLegacyLimitIsAccepted() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody("x".repeat(LEGACY_LIMIT_BYTES)))
        server.start()
        try {
            val response = transport().execute(
                AgentHttpRequest(
                    requestId = "exact-limit",
                    url = server.url("/response").toString()
                )
            )

            assertEquals(LEGACY_LIMIT_BYTES, response.body.toByteArray().size)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun oneByteOverLegacyLimitIsRejectedPrecisely() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody("x".repeat(LEGACY_LIMIT_BYTES + 1)))
        server.start()
        try {
            val error = runCatching {
                transport().execute(
                    AgentHttpRequest(
                        requestId = "over-limit",
                        url = server.url("/response").toString()
                    )
                )
            }.exceptionOrNull()

            assertTrue(error is AgentHttpException)
            assertEquals(AgentHttpFailureKind.ResponseTooLarge, (error as AgentHttpException).kind)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun bodyReadTimeoutIsClassifiedAtTheBodyReadBoundary() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setBody("0123456789")
                .throttleBody(1, 1, TimeUnit.SECONDS)
        )
        server.start()
        try {
            val error = runCatching {
                transport().execute(
                    AgentHttpRequest(
                        requestId = "body-timeout",
                        url = server.url("/slow").toString(),
                        timeoutMillis = 100L
                    )
                )
            }.exceptionOrNull()

            assertTrue("body read should fail", error is AgentHttpException)
            val mapped = error as AgentHttpException
            assertEquals(AgentHttpFailureKind.Timeout, mapped.kind)
            assertEquals("body_read", mapped.failureStage)
            assertEquals("timeout", mapped.networkFailureKind)
            assertTrue(mapped.bytesReceived >= 0L)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun non2xxBodyUsesItsSmallerIndependentLimit() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(400)
                .setBody("e".repeat(64 * 1024 + 1))
        )
        server.start()
        try {
            val response = transport().execute(
                AgentHttpRequest(
                    requestId = "large-error",
                    url = server.url("/error").toString()
                )
            )

            assertEquals(400, response.statusCode)
            assertEquals(64L * 1024L, response.responseLimitBytes)
            assertEquals(64 * 1024, response.body.toByteArray().size)
            assertEquals(64L * 1024L + 1L, response.bytesReceived)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun non2xxTruncationKeepsPrefixWhenAReadCrossesTheLimit() = runBlocking {
        assertErrorPrefixAcrossSingleRead(streaming = false)
    }

    @Test
    fun streamingNon2xxTruncationKeepsPrefixWhenAReadCrossesTheLimit() = runBlocking {
        assertErrorPrefixAcrossSingleRead(streaming = true)
    }

    @Test
    fun streamingSsePreservesRawBytesAndUsesTheBusinessLimit() = runBlocking {
        val server = MockWebServer()
        val dumpRoot = Files.createTempDirectory("agent-sse-dump").toFile()
        val capture = AgentResponseDebugCapture(dumpRoot, buildDebug = true)
        val sse = "event: message\ndata: {\"delta\":\"ok\"}\n\n"
        server.enqueue(
            MockResponse()
                .addHeader("Content-Type", "text/event-stream")
                .setBody(sse)
        )
        server.start()
        try {
            assertTrue(capture.armNextResponse())
            val chunks = mutableListOf<String>()
            transport(debugCapture = capture).executeStreaming(
                AgentHttpRequest(
                    requestId = "sse-request",
                    url = server.url("/stream").toString()
                ),
                onChunk = { chunks += it }
            )

            val raw = dumpRoot.listFiles()!!.single { it.extension == "sse" }
            assertEquals(sse, raw.readText())
            assertEquals(sse, chunks.joinToString(separator = ""))
            assertFalse(capture.isArmed)
        } finally {
            server.shutdown()
            dumpRoot.deleteRecursively()
        }
    }

    @Test
    fun streamingResponseOverLimitIsRejectedPrecisely() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody("x".repeat(LEGACY_LIMIT_BYTES + 1)))
        server.start()
        try {
            val error = runCatching {
                transport().executeStreaming(
                    AgentHttpRequest(
                        requestId = "stream-over-limit",
                        url = server.url("/stream").toString()
                    ),
                    onChunk = {}
                )
            }.exceptionOrNull()

            assertTrue(error is AgentHttpException)
            val mapped = error as AgentHttpException
            assertEquals(AgentHttpFailureKind.ResponseTooLarge, mapped.kind)
            assertEquals(LEGACY_LIMIT_BYTES.toLong(), mapped.responseLimitBytes)
            assertTrue(mapped.bytesReceived > LEGACY_LIMIT_BYTES)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun streamingCallOutlivingTimeoutMillisStillCompletes() = runBlocking {
        val server = MockWebServer()
        // 40 bytes at 50 ms apiece ≈ 2 s of body traffic: four times past
        // timeoutMillis, yet no single gap comes near the read timeout. This is
        // exactly the reasoning-model shape — headers first, long slow stream
        // after — that a whole-call deadline used to kill mid-flight.
        val sse = ("data: {\"delta\":\"ok\"}\n\n").repeat(4)
        server.enqueue(
            MockResponse()
                .addHeader("Content-Type", "text/event-stream")
                .setBody(sse)
                .throttleBody(1, 50, TimeUnit.MILLISECONDS)
        )
        server.start()
        try {
            val startedAt = System.nanoTime()
            val chunks = mutableListOf<String>()
            transport().executeStreaming(
                AgentHttpRequest(
                    requestId = "stream-outlives-timeout",
                    url = server.url("/stream").toString(),
                    timeoutMillis = 500L
                ),
                onChunk = { chunks += it }
            )
            val elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000L
            assertEquals(sse, chunks.joinToString(separator = ""))
            assertTrue(
                "stream should outlive timeoutMillis (took ${elapsedMillis}ms)",
                elapsedMillis > 500L
            )
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun streamingSilenceBeyondTimeoutIsStillClassifiedAsTimeout() = runBlocking {
        val server = MockWebServer()
        // The body trickles one byte every 2 s; the 300 ms read timeout fires on
        // an inter-chunk gap, proving the idle bound survives without callTimeout.
        server.enqueue(
            MockResponse()
                .addHeader("Content-Type", "text/event-stream")
                .setBody("x".repeat(8))
                .throttleBody(1, 2, TimeUnit.SECONDS)
        )
        server.start()
        try {
            val error = runCatching {
                transport().executeStreaming(
                    AgentHttpRequest(
                        requestId = "stream-idle-timeout",
                        url = server.url("/stream").toString(),
                        timeoutMillis = 300L
                    ),
                    onChunk = {}
                )
            }.exceptionOrNull()

            assertTrue(error is AgentHttpException)
            assertEquals(AgentHttpFailureKind.Timeout, (error as AgentHttpException).kind)
            assertEquals("body_read", (error as AgentHttpException).failureStage)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun cancelDuringBodyReadIsMappedToCancelled() = runBlocking {        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setBody("x".repeat(128))
                .throttleBody(1, 1, TimeUnit.SECONDS)
        )
        server.start()
        try {
            val transport = transport()
            val requestId = "cancel-during-body"
            val result = async(Dispatchers.IO) {
                runCatching {
                    transport.execute(
                        AgentHttpRequest(
                            requestId = requestId,
                            url = server.url("/slow-body").toString(),
                            timeoutMillis = 5_000L
                        )
                    )
                }
            }
            assertTrue(server.takeRequest(3, TimeUnit.SECONDS) != null)
            delay(200L)
            transport.cancel(requestId)
            val failure = withTimeout(2_000L) { result.await().exceptionOrNull() }
            assertTrue(failure is AgentHttpException)
            assertEquals(AgentHttpFailureKind.Cancelled, (failure as AgentHttpException).kind)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun cancellationDoesNotBecomeAReadFailure() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
        server.start()
        try {
            val transport = transport()
            val result = async(Dispatchers.IO) {
                runCatching {
                    transport.execute(
                        AgentHttpRequest(
                            requestId = "cancel-before-headers",
                            url = server.url("/cancel").toString()
                        )
                    )
                }
            }
            assertTrue(server.takeRequest(3, TimeUnit.SECONDS) != null)
            transport.cancel("cancel-before-headers")
            val failure = withTimeout(2_000L) { result.await().exceptionOrNull() }
            assertTrue(failure is AgentHttpException)
            assertEquals(AgentHttpFailureKind.Cancelled, (failure as AgentHttpException).kind)
        } finally {
            server.shutdown()
        }
    }

    private suspend fun assertErrorPrefixAcrossSingleRead(streaming: Boolean) {
        // An in-memory body crosses the limit in one read, independently of
        // how the OS happens to split a MockWebServer response into TCP reads.
        val client = OkHttpClient.Builder()
            .addInterceptor { chain ->
                Response.Builder()
                    .request(chain.request())
                    .protocol(Protocol.HTTP_1_1)
                    .code(400)
                    .message("Bad Request")
                    .body("abcdefghij".toResponseBody())
                    .build()
            }
            .build()
        val transport = OkHttpAgentHttpTransport(
            baseClient = client,
            maxErrorResponseBytes = 8L
        )
        val request = AgentHttpRequest(
            requestId = "error-prefix-$streaming",
            url = "https://gateway.invalid/error"
        )
        val response = if (streaming) {
            transport.executeStreaming(request) {
                throw AssertionError("HTTP error bodies must not be emitted as success chunks")
            }
        } else {
            transport.execute(request)
        }

        assertEquals(400, response.statusCode)
        assertEquals("abcdefgh", response.body)
        assertEquals(8L, response.responseLimitBytes)
        assertEquals(9L, response.bytesReceived)
    }

    private fun transport(
        debugCapture: AgentResponseDebugCapture? = null
    ) = OkHttpAgentHttpTransport(
        maxResponseBytes = LEGACY_LIMIT_BYTES.toLong(),
        debugCapture = debugCapture,
        allowInsecureHttpForTests = true
    )

    private companion object {
        const val LEGACY_LIMIT_BYTES = 512 * 1024
    }
}
