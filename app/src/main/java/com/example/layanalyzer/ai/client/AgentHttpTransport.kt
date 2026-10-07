// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.MediaType.Companion.toMediaType
import java.io.ByteArrayOutputStream
import java.io.InterruptedIOException
import java.io.IOException
import java.io.InputStream
import java.net.URI
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Normalized request understood by the Android gateway adapter. */
data class AgentHttpRequest(
    val requestId: String,
    val url: String,
    val body: String? = null,
    val headers: Map<String, String> = emptyMap(),
    val timeoutMillis: Long = OkHttpAgentHttpTransport.DEFAULT_TIMEOUT_MILLIS
)

/** Body-limited response; raw provider response objects never cross this type. */
data class AgentHttpResponse(
    val statusCode: Int,
    val headers: Map<String, String> = emptyMap(),
    val body: String = "",
    /** Bytes observed before the bounded reader returned or failed. */
    val bytesReceived: Long = body.toByteArray(Charsets.UTF_8).size.toLong(),
    val responseLimitBytes: Long? = null
)

data class AgentResponseLimits(
    val successBytes: Long = OkHttpAgentHttpTransport.DEFAULT_MAX_RESPONSE_BYTES,
    val errorBytes: Long = OkHttpAgentHttpTransport.DEFAULT_MAX_ERROR_RESPONSE_BYTES
) {
    init {
        require(successBytes > 0L) { "successBytes must be positive." }
        require(errorBytes > 0L) { "errorBytes must be positive." }
    }
}

enum class AgentHttpFailureKind {
    Cancelled,
    Timeout,
    Network,
    ResponseTooLarge,
    InsecureEndpoint
}

class AgentHttpException(
    val kind: AgentHttpFailureKind,
    message: String,
    cause: Throwable? = null,
    /** connect/write/headers/body_read/decode. */
    val failureStage: String = "unknown",
    /** dns/connect/tls/reset/timeout/offline/unknown. */
    val networkFailureKind: String = "unknown",
    val bytesReceived: Long = 0L,
    val responseLimitBytes: Long? = null
) : IOException(message, cause)

/** HTTP boundary with request-scoped cancellation and a bounded response body. */
interface AgentHttpTransport {
    suspend fun execute(request: AgentHttpRequest): AgentHttpResponse

    /** Stream a successful response body without retaining it in memory. */
    suspend fun executeStreaming(
        request: AgentHttpRequest,
        onChunk: suspend (String) -> Unit
    ): AgentHttpResponse {
        val response = execute(request)
        if (response.statusCode in 200..299 && response.body.isNotEmpty()) {
            onChunk(response.body)
        }
        return response
    }

    fun cancel(requestId: String)

    /**
     * Best-effort server-side cancellation. The local HTTP call is cancelled
     * by [cancel]; this hook lets a gateway also stop or ignore the upstream
     * provider request. Implementations may return immediately.
     */
    fun cancelRemote(request: AgentHttpRequest) = Unit
}

/** Strict URL check shared by the adapter and the concrete transport. */
internal fun isSecureGatewayUrl(value: String): Boolean = runCatching {
    val uri = URI(value.trim())
    uri.scheme.equals("https", ignoreCase = true) &&
        !uri.host.isNullOrBlank() &&
        uri.userInfo == null &&
        uri.query == null &&
        uri.fragment == null
}.getOrDefault(false)

/**
 * OkHttp implementation used by gateway-backed model clients.
 *
 * The default is deliberately strict: production calls must use HTTPS. Tests
 * that use an ordinary MockWebServer can opt into HTTP explicitly on the
 * transport instance; that switch is never used by the Application wiring.
 */
class OkHttpAgentHttpTransport(
    private val baseClient: OkHttpClient = defaultClient(),
    private val maxResponseBytes: Long = DEFAULT_MAX_RESPONSE_BYTES,
    private val allowInsecureHttpForTests: Boolean = false,
    private val maxErrorResponseBytes: Long = DEFAULT_MAX_ERROR_RESPONSE_BYTES,
    private val debugCapture: AgentResponseDebugCapture? = null
) : AgentHttpTransport {
    private val calls = ConcurrentHashMap<String, Call>()
    private val explicitlyCancelled = ConcurrentHashMap.newKeySet<String>()

    init {
        require(maxResponseBytes > 0L) { "maxResponseBytes must be positive." }
        require(maxErrorResponseBytes > 0L) { "maxErrorResponseBytes must be positive." }
    }

    override suspend fun execute(request: AgentHttpRequest): AgentHttpResponse =
        suspendCancellableCoroutine { continuation ->
            if (request.requestId.isBlank()) {
                continuation.resumeWith(
                    Result.failure(IllegalArgumentException("requestId must not be blank."))
                )
                return@suspendCancellableCoroutine
            }
            if (!allowInsecureHttpForTests && !isSecureGatewayUrl(request.url)) {
                continuation.resumeWith(
                    Result.failure(
                        AgentHttpException(
                            AgentHttpFailureKind.InsecureEndpoint,
                            "Only HTTPS gateway endpoints are allowed."
                        )
                    )
                )
                return@suspendCancellableCoroutine
            }
            if (explicitlyCancelled.remove(request.requestId)) {
                continuation.resumeWith(
                    Result.failure(
                        AgentHttpException(AgentHttpFailureKind.Cancelled, "HTTP request cancelled.")
                    )
                )
                return@suspendCancellableCoroutine
            }

            val timeout = request.timeoutMillis.coerceAtLeast(1L)
            val client = baseClient.newBuilder()
                .connectTimeout(timeout, TimeUnit.MILLISECONDS)
                .readTimeout(timeout, TimeUnit.MILLISECONDS)
                .writeTimeout(timeout, TimeUnit.MILLISECONDS)
                .callTimeout(timeout, TimeUnit.MILLISECONDS)
                .build()
            val builder = Request.Builder().url(request.url)
            request.headers.forEach { (name, value) -> builder.header(name, value) }
            val httpRequest = if (request.body == null) {
                builder.get().build()
            } else {
                builder.post(request.body.toRequestBody(JSON_MEDIA_TYPE)).build()
            }
            val call = client.newCall(httpRequest)
            calls[request.requestId] = call
            continuation.invokeOnCancellation {
                calls.remove(request.requestId, call)
                call.cancel()
            }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    calls.remove(request.requestId, call)
                    val wasExplicitlyCancelled = explicitlyCancelled.remove(request.requestId)
                    if (!continuation.isActive) return
                    val kind = if (wasExplicitlyCancelled) {
                        AgentHttpFailureKind.Cancelled
                    } else if (isTimeout(e)) {
                        AgentHttpFailureKind.Timeout
                    } else {
                        AgentHttpFailureKind.Network
                    }
                    continuation.resumeWith(
                        Result.failure(
                            AgentHttpException(
                                kind,
                                "Gateway request failed.",
                                e,
                                failureStage = failureStageFor(e, beforeHeaders = true),
                                networkFailureKind = networkKindFor(e, kind)
                            )
                        )
                    )
                }

                override fun onResponse(call: Call, response: okhttp3.Response) {
                    val headers = response.headers.toMultimap().mapValues { it.value.firstOrNull().orEmpty() }
                    val processingLimit = if (response.code in 200..299) {
                        maxResponseBytes
                    } else {
                        maxErrorResponseBytes
                    }
                    val capture = debugCapture?.begin(
                        AgentResponseDebugRequest(
                            runId = request.requestId.substringBefore('#'),
                            requestId = request.requestId,
                            requestIdHash = requestHash(request.requestId),
                            streaming = false
                        )
                    )
                    try {
                        val read = response.body?.use {
                            readBounded(
                                input = it.byteStream(),
                                limitBytes = processingLimit,
                                truncateOnLimit = response.code !in 200..299,
                                capture = capture
                            )
                        } ?: BoundedReadResult("", 0L, false)
                        if (read.truncated && response.code in 200..299) {
                            throw responseTooLarge(read.bytesReceived, processingLimit)
                        }
                        capture?.finish(
                            httpStatus = response.code,
                            contentType = response.header("Content-Type"),
                            declaredContentLength = response.body?.contentLength()?.takeIf { it >= 0L },
                            processingLimitBytes = processingLimit
                        )
                        if (continuation.isActive) {
                            continuation.resumeWith(
                                Result.success(
                                    AgentHttpResponse(
                                        statusCode = response.code,
                                        headers = headers,
                                        body = read.body,
                                        bytesReceived = read.bytesReceived,
                                        responseLimitBytes = processingLimit
                                    )
                                )
                            )
                        }
                    } catch (error: AgentHttpException) {
                        capture?.finish(
                            httpStatus = response.code,
                            contentType = response.header("Content-Type"),
                            declaredContentLength = response.body?.contentLength()?.takeIf { it >= 0L },
                            processingLimitBytes = processingLimit,
                            processingFailure = error.kind.name.lowercase(),
                            cancelled = error.kind == AgentHttpFailureKind.Cancelled
                        )
                        if (continuation.isActive) continuation.resumeWith(Result.failure(error))
                    } catch (error: IOException) {
                        val mapped = mapReadException(
                            requestId = request.requestId,
                            error = error,
                            bytesReceived = (error as? BoundedReadException)?.bytesReceived ?: 0L,
                            responseLimitBytes = processingLimit
                        )
                        capture?.finish(
                            httpStatus = response.code,
                            contentType = response.header("Content-Type"),
                            declaredContentLength = response.body?.contentLength()?.takeIf { it >= 0L },
                            processingLimitBytes = processingLimit,
                            processingFailure = mapped.kind.name.lowercase(),
                            cancelled = mapped.kind == AgentHttpFailureKind.Cancelled
                        )
                        if (continuation.isActive) continuation.resumeWith(Result.failure(mapped))
                    } catch (error: Throwable) {
                        capture?.finish(
                            httpStatus = response.code,
                            contentType = response.header("Content-Type"),
                            declaredContentLength = response.body?.contentLength()?.takeIf { it >= 0L },
                            processingLimitBytes = processingLimit,
                            processingFailure = "internal"
                        )
                        if (continuation.isActive) continuation.resumeWith(Result.failure(error))
                    } finally {
                        calls.remove(request.requestId, call)
                        response.close()
                    }
                }
            })
        }

    override suspend fun executeStreaming(
        request: AgentHttpRequest,
        onChunk: suspend (String) -> Unit
    ): AgentHttpResponse {
        validateStreamingRequest(request)
        val call = streamingCall(request)
        calls[request.requestId] = call
        var capture: AgentResponseDebugCapture.Session? = null
        var responseStatus: Int? = null
        var responseContentType: String? = null
        var declaredContentLength: Long? = null
        var processingLimit = maxResponseBytes
        var bytesReceived = 0L
        return try {
            awaitResponse(call).use { response ->
                responseStatus = response.code
                responseContentType = response.header("Content-Type")
                declaredContentLength = response.body?.contentLength()?.takeIf { it >= 0L }
                processingLimit = if (response.code in 200..299) {
                    maxResponseBytes
                } else {
                    maxErrorResponseBytes
                }
                val headers = response.headers.toMultimap()
                    .mapValues { it.value.firstOrNull().orEmpty() }
                capture = debugCapture?.begin(
                    AgentResponseDebugRequest(
                        runId = request.requestId.substringBefore('#'),
                        requestId = request.requestId,
                        requestIdHash = requestHash(request.requestId),
                        streaming = true
                    )
                )
                if (response.code !in 200..299) {
                    val body = response.body?.byteStream()?.let { input ->
                        runInterruptible(Dispatchers.IO) {
                            readBounded(
                                input = input,
                                limitBytes = processingLimit,
                                truncateOnLimit = true,
                                capture = capture
                            )
                        }
                    } ?: BoundedReadResult("", 0L, false)
                    capture?.finish(
                        httpStatus = response.code,
                        contentType = responseContentType,
                        declaredContentLength = declaredContentLength,
                        processingLimitBytes = processingLimit
                    )
                    return AgentHttpResponse(
                        statusCode = response.code,
                        headers = headers,
                        body = body.body,
                        bytesReceived = body.bytesReceived,
                        responseLimitBytes = processingLimit
                    )
                }

                val input = response.body?.byteStream()
                var exceeded = false
                if (input != null) {
                    val buffer = ByteArray(STREAM_BUFFER_SIZE)
                    while (true) {
                        val read = runInterruptible(Dispatchers.IO) {
                            input.read(buffer, 0, nextReadSize(bytesReceived, processingLimit, buffer.size, capture))
                        }
                        if (read < 0) break
                        bytesReceived += read.toLong()
                        capture?.write(buffer, 0, read)
                        if (bytesReceived > processingLimit) {
                            exceeded = true
                            if (capture == null || capture?.isAtLimit == true) {
                                throw responseTooLarge(bytesReceived, processingLimit)
                            }
                        }
                        if (read > 0 && bytesReceived <= processingLimit) {
                            onChunk(String(buffer, 0, read, Charsets.UTF_8))
                        }
                    }
                    if (exceeded) throw responseTooLarge(bytesReceived, processingLimit)
                }
                capture?.finish(
                    httpStatus = response.code,
                    contentType = responseContentType,
                    declaredContentLength = declaredContentLength,
                    processingLimitBytes = processingLimit
                )
                AgentHttpResponse(
                    statusCode = response.code,
                    headers = headers,
                    bytesReceived = bytesReceived,
                    responseLimitBytes = processingLimit
                )
            }
        } catch (cancelled: CancellationException) {
            capture?.finish(
                httpStatus = responseStatus,
                contentType = responseContentType,
                declaredContentLength = declaredContentLength,
                processingLimitBytes = processingLimit,
                processingFailure = AgentHttpFailureKind.Cancelled.name.lowercase(),
                cancelled = true
            )
            call.cancel()
            throw cancelled
        } catch (error: AgentHttpException) {
            capture?.finish(
                httpStatus = responseStatus,
                contentType = responseContentType,
                declaredContentLength = declaredContentLength,
                processingLimitBytes = processingLimit,
                processingFailure = error.kind.name.lowercase(),
                cancelled = error.kind == AgentHttpFailureKind.Cancelled
            )
            throw error
        } catch (error: IOException) {
            val wasExplicitlyCancelled = explicitlyCancelled.remove(request.requestId)
            val kind = when {
                wasExplicitlyCancelled -> AgentHttpFailureKind.Cancelled
                isTimeout(error) -> AgentHttpFailureKind.Timeout
                else -> AgentHttpFailureKind.Network
            }
            val mapped = AgentHttpException(
                kind,
                "Gateway request failed.",
                error,
                failureStage = if (responseStatus == null) {
                    failureStageFor(error, beforeHeaders = true)
                } else {
                    "body_read"
                },
                networkFailureKind = networkKindFor(error, kind),
                bytesReceived = bytesReceived,
                responseLimitBytes = processingLimit
            )
            capture?.finish(
                httpStatus = responseStatus,
                contentType = responseContentType,
                declaredContentLength = declaredContentLength,
                processingLimitBytes = processingLimit,
                processingFailure = mapped.kind.name.lowercase(),
                cancelled = mapped.kind == AgentHttpFailureKind.Cancelled
            )
            throw mapped
        } finally {
            calls.remove(request.requestId, call)
            explicitlyCancelled.remove(request.requestId)
        }
    }

    private suspend fun awaitResponse(call: Call): okhttp3.Response =
        suspendCancellableCoroutine { continuation ->
            val deliveredResponse = AtomicReference<okhttp3.Response?>(null)
            continuation.invokeOnCancellation {
                call.cancel()
                deliveredResponse.getAndSet(null)?.close()
            }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    if (continuation.isActive) {
                        continuation.resumeWith(Result.failure(e))
                    }
                }

                override fun onResponse(call: Call, response: okhttp3.Response) {
                    deliveredResponse.set(response)
                    if (continuation.isActive) {
                        continuation.resumeWith(Result.success(response))
                    } else {
                        deliveredResponse.compareAndSet(response, null)
                        response.close()
                    }
                }
            })
        }

    override fun cancel(requestId: String) {
        if (requestId.isBlank()) return
        // Do not retain a cancellation marker for an unknown or already-finished
        // request. Otherwise a later request that reuses the id would be rejected
        // even though this call was supposed to be idempotent.
        calls.remove(requestId)?.let { call ->
            explicitlyCancelled += requestId
            call.cancel()
        }
    }

    private fun validateStreamingRequest(request: AgentHttpRequest) {
        if (request.requestId.isBlank()) {
            throw IllegalArgumentException("requestId must not be blank.")
        }
        if (!allowInsecureHttpForTests && !isSecureGatewayUrl(request.url)) {
            throw AgentHttpException(
                AgentHttpFailureKind.InsecureEndpoint,
                "Only HTTPS gateway endpoints are allowed."
            )
        }
        if (explicitlyCancelled.remove(request.requestId)) {
            throw AgentHttpException(AgentHttpFailureKind.Cancelled, "HTTP request cancelled.")
        }
    }

    private fun streamingCall(request: AgentHttpRequest): Call {
        val timeout = request.timeoutMillis.coerceAtLeast(1L)
        val client = baseClient.newBuilder()
            .connectTimeout(timeout, TimeUnit.MILLISECONDS)
            // An SSE stream must not carry a whole-call deadline: a reasoning
            // model can legitimately stay silent far past timeoutMillis and
            // then keep producing for minutes more. readTimeout only bounds
            // the silence between chunks, so a wedged or dropped stream still
            // fails while an active one lives as long as it needs.
            .readTimeout(timeout, TimeUnit.MILLISECONDS)
            .writeTimeout(timeout, TimeUnit.MILLISECONDS)
            .callTimeout(0, TimeUnit.MILLISECONDS)
            .build()
        val builder = Request.Builder().url(request.url)
        request.headers.forEach { (name, value) -> builder.header(name, value) }
        val httpRequest = if (request.body == null) {
            builder.get().build()
        } else {
            builder.post(request.body.toRequestBody(JSON_MEDIA_TYPE)).build()
        }
        return client.newCall(httpRequest)
    }

    override fun cancelRemote(request: AgentHttpRequest) {
        if (request.requestId.isBlank()) return
        if (!allowInsecureHttpForTests && !isSecureGatewayUrl(request.url)) return

        val timeout = request.timeoutMillis.coerceAtLeast(1L)
        val client = baseClient.newBuilder()
            .connectTimeout(timeout, TimeUnit.MILLISECONDS)
            .readTimeout(timeout, TimeUnit.MILLISECONDS)
            .writeTimeout(timeout, TimeUnit.MILLISECONDS)
            .callTimeout(timeout, TimeUnit.MILLISECONDS)
            .build()
        val builder = Request.Builder().url(request.url)
        request.headers.forEach { (name, value) -> builder.header(name, value) }
        val httpRequest = builder
            .post((request.body ?: "{}").toRequestBody(JSON_MEDIA_TYPE))
            .build()

        // Cancellation is deliberately fire-and-forget. The caller has already
        // cancelled its structured request; the gateway endpoint is idempotent
        // and only needs a chance to mark an upstream request as cancelled.
        client.newCall(httpRequest).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) = Unit

            override fun onResponse(call: Call, response: okhttp3.Response) {
                response.close()
            }
        })
    }

    private fun readBounded(
        input: InputStream,
        limitBytes: Long,
        truncateOnLimit: Boolean,
        capture: AgentResponseDebugCapture.Session?
    ): BoundedReadResult {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(BUFFER_SIZE)
        var total = 0L
        var exceeded = false
        while (true) {
            val read = try {
                input.read(
                    buffer,
                    0,
                    nextReadSize(total, limitBytes, buffer.size, capture)
                )
            } catch (error: IOException) {
                throw BoundedReadException(total, error)
            }
            if (read < 0) break
            // A read can contain both the allowed prefix and the first byte
            // beyond the limit. Retain that prefix before stopping the read.
            val retainedBytes = (limitBytes - total).coerceIn(0L, read.toLong()).toInt()
            if (retainedBytes > 0) output.write(buffer, 0, retainedBytes)
            total += read
            capture?.write(buffer, 0, read)
            if (total > limitBytes) {
                exceeded = true
                if (truncateOnLimit && capture == null) break
                if (!truncateOnLimit && capture == null) {
                    throw AgentHttpException(
                        AgentHttpFailureKind.ResponseTooLarge,
                        "Gateway response exceeded the configured limit.",
                        failureStage = "body_read",
                        bytesReceived = total,
                        responseLimitBytes = limitBytes
                    )
                }
                if (capture?.isAtLimit == true) {
                    throw AgentHttpException(
                        AgentHttpFailureKind.ResponseTooLarge,
                        "Gateway response exceeded the configured limit.",
                        failureStage = "body_read",
                        bytesReceived = total,
                        responseLimitBytes = limitBytes
                    )
                }
            }
        }
        if (exceeded && !truncateOnLimit) {
            throw AgentHttpException(
                AgentHttpFailureKind.ResponseTooLarge,
                "Gateway response exceeded the configured limit.",
                failureStage = "body_read",
                bytesReceived = total,
                responseLimitBytes = limitBytes
            )
        }
        return BoundedReadResult(
            body = output.toString(Charsets.UTF_8.name()),
            bytesReceived = total,
            truncated = exceeded
        )
    }

    private fun nextReadSize(
        bytesReceived: Long,
        limitBytes: Long,
        bufferSize: Int,
        capture: AgentResponseDebugCapture.Session?
    ): Int {
        if (capture?.isAtLimit == true) return 1
        val remaining = (limitBytes - bytesReceived).coerceAtLeast(0L)
        // Without a debug sink, one byte beyond the business limit is enough
        // to classify the response precisely and avoids reading an arbitrary
        // extra chunk into memory. With a sink, continue in normal chunks so
        // the raw response can be captured independently up to its own cap.
        return if (capture == null && remaining < bufferSize) {
            (remaining + 1L).coerceIn(1L, bufferSize.toLong()).toInt()
        } else {
            bufferSize
        }
    }

    private fun responseTooLarge(bytesReceived: Long, limitBytes: Long): AgentHttpException =
        AgentHttpException(
            AgentHttpFailureKind.ResponseTooLarge,
            "Gateway response exceeded the configured limit.",
            failureStage = "body_read",
            bytesReceived = bytesReceived,
            responseLimitBytes = limitBytes
        )

    private fun isTimeout(error: IOException): Boolean {
        var current: Throwable? = error
        while (current != null) {
            if (current is java.net.SocketTimeoutException ||
                (current is InterruptedIOException && current.message
                    ?.contains("timeout", ignoreCase = true) == true)
            ) {
                return true
            }
            current = current.cause
        }
        return false
    }

    private fun mapReadException(
        requestId: String,
        error: IOException,
        bytesReceived: Long,
        responseLimitBytes: Long
    ): AgentHttpException {
        val explicitlyCancelled = explicitlyCancelled.remove(requestId)
        val kind = when {
            explicitlyCancelled -> AgentHttpFailureKind.Cancelled
            isTimeout(error) -> AgentHttpFailureKind.Timeout
            else -> AgentHttpFailureKind.Network
        }
        return AgentHttpException(
            kind = kind,
            message = "Gateway response body could not be read.",
            cause = error,
            failureStage = "body_read",
            networkFailureKind = networkKindFor(error, kind),
            bytesReceived = bytesReceived,
            responseLimitBytes = responseLimitBytes
        )
    }

    private fun failureStageFor(error: IOException, beforeHeaders: Boolean): String {
        if (!beforeHeaders) return "body_read"
        val message = error.message.orEmpty().lowercase()
        return when {
            "connect" in message || "failed to connect" in message -> "connect"
            "write" in message -> "write"
            else -> "headers"
        }
    }

    private fun networkKindFor(
        error: IOException,
        failureKind: AgentHttpFailureKind
    ): String {
        if (failureKind == AgentHttpFailureKind.Timeout) return "timeout"
        val text = (error.javaClass.name + " " + error.message.orEmpty()).lowercase()
        return when {
            "unknownhost" in text || "dns" in text -> "dns"
            "ssl" in text || "tls" in text || "handshake" in text -> "tls"
            "reset" in text || "eof" in text || "closed" in text -> "reset"
            "connect" in text -> "connect"
            "offline" in text || "unreachable" in text -> "offline"
            else -> "unknown"
        }
    }

    private fun requestHash(requestId: String): String = Integer.toHexString(requestId.hashCode())

    private data class BoundedReadResult(
        val body: String,
        val bytesReceived: Long,
        val truncated: Boolean
    )

    private class BoundedReadException(
        val bytesReceived: Long,
        cause: IOException
    ) : IOException("Gateway response body could not be read.", cause)

    companion object {
        const val DEFAULT_MAX_RESPONSE_BYTES: Long = 4L * 1024 * 1024
        const val DEFAULT_MAX_ERROR_RESPONSE_BYTES: Long = 64L * 1024
        const val DEFAULT_TIMEOUT_MILLIS: Long = 120_000L
        private const val BUFFER_SIZE = 8 * 1024
        private const val STREAM_BUFFER_SIZE = 2 * 1024
        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)
            .callTimeout(120, TimeUnit.SECONDS)
            .build()
    }
}

typealias DefaultAgentHttpTransport = OkHttpAgentHttpTransport
