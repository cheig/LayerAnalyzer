package com.example.layanalyzer.ai.client

import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentToolCall
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.json.JSONArray
import org.json.JSONObject
import java.io.Closeable
import java.security.MessageDigest
import java.util.ArrayDeque
import java.util.Collections
import java.util.concurrent.CopyOnWriteArrayList

/** A bounded, body-free audit entry emitted by [FakeAgentGateway]. */
data class FakeGatewayAuditRecord(
    val requestId: String,
    val modelId: String,
    val toolNames: List<String>,
    val parameterHashes: List<String>,
    val dataCategoryCounts: Map<String, Int>,
    val errorCode: String? = null
)

/** Responses that can be queued for deterministic gateway contract tests. */
sealed interface FakeGatewayResponse {
    data class ToolCalls(
        val calls: List<AgentToolCall>,
        val assistantContent: String = "",
        val reasoningContent: String? = null
    ) : FakeGatewayResponse
    data class Final(
        val report: AgentReport,
        val reasoningContent: String? = null
    ) : FakeGatewayResponse
    data class Refusal(val reason: String = "policy") : FakeGatewayResponse
    data class Error(
        val statusCode: Int,
        val code: String,
        val retryAfterSeconds: Long? = null,
        val quotaType: String? = null
    ) : FakeGatewayResponse
}

/**
 * JVM-only fake of the production gateway contract.
 *
 * It intentionally stores only request ids, tool names, parameter hashes and
 * category counts. Request/response bodies are never retained in its audit
 * records, which makes it useful for testing the server-side retention rule as
 * well as the Android adapter.
 */
class FakeAgentGateway(
    private val accessToken: String = "fake-access-token",
    private val account: GatewayAccount = GatewayAccount(
        userId = "fake-user",
        organizationId = "fake-org",
        planId = "test"
    ),
    models: List<GatewayModel> = listOf(
        GatewayModel(
            id = "fake-model",
            displayName = "Fake model",
            capabilities = AiModelCapabilities.PHASE0,
            dataPolicy = "redacted_metadata"
        )
    ),
    private val quota: GatewayQuota = GatewayQuota(
        requestsPerMinute = 60,
        concurrentSessions = 2,
        tokensPerMonth = 100_000,
        costMicrosPerMonth = 10_000_000,
        maxContextTokens = 32_000,
        maxOutputTokens = 2_000
    )
) : Closeable {
    private val server = MockWebServer()
    private val models = models.toList()
    private val responseQueue = ArrayDeque<FakeGatewayResponse>()
    private val requestTimesMillis = ArrayDeque<Long>()
    private val cancelledRequestIds = Collections.synchronizedSet(mutableSetOf<String>())
    private val audit = CopyOnWriteArrayList<FakeGatewayAuditRecord>()
    private var started = false

    val auditRecords: List<FakeGatewayAuditRecord>
        get() = audit.toList()

    val cancelledIds: Set<String>
        get() = synchronized(cancelledRequestIds) { cancelledRequestIds.toSet() }

    val requestCount: Int
        get() = audit.size

    val baseUrl: String
        get() = check(started) { "Fake gateway has not been started." }.let {
            server.url("/").toString().removeSuffix("/")
        }

    fun start() {
        if (started) return
        server.dispatcher = dispatcher()
        server.start()
        started = true
    }

    fun enqueue(response: FakeGatewayResponse) {
        synchronized(responseQueue) { responseQueue.addLast(response) }
    }

    override fun close() {
        if (!started) return
        started = false
        server.shutdown()
    }

    private fun dispatcher(): Dispatcher = object : Dispatcher() {
        override fun dispatch(request: RecordedRequest): MockResponse {
            val path = request.requestUrl?.encodedPath ?: ""
            return when {
                request.method == "GET" && path == "/v1/models" -> modelsResponse(request)
                request.method == "GET" && path == "/v1/usage" -> usageResponse(request)
                request.method == "POST" && path == "/v1/agent/cancel" -> cancelResponse(request)
                request.method == "POST" && path == "/v1/agent/respond" -> respond(request)
                else -> jsonResponse(404, errorJson("not_found"))
            }
        }
    }

    private fun modelsResponse(request: RecordedRequest): MockResponse {
        if (!authorized(request)) return unauthorized()
        val body = JSONObject().apply {
            put("account", accountJson())
            put("models", JSONArray().apply { models.forEach { put(modelJson(it)) } })
        }
        return jsonResponse(200, body)
    }

    private fun usageResponse(request: RecordedRequest): MockResponse {
        if (!authorized(request)) return unauthorized()
        val now = System.currentTimeMillis()
        val requestCount = synchronized(requestTimesMillis) {
            requestTimesMillis.removeExpired(now)
            requestTimesMillis.size
        }
        val body = JSONObject().apply {
            put("account", accountJson())
            put("quota", quotaJson())
            put("usage", JSONObject().apply {
                put("requestsThisMinute", requestCount)
                put("activeSessions", 0)
                put("tokensToday", 0)
                put("tokensThisMonth", 0)
                put("costMicrosThisMonth", 0)
                put("windowStartMillis", now - 60_000L)
                put("windowEndMillis", now)
            })
            put("allowedModels", JSONArray(models.filter { it.allowed }.map { it.id }))
            put("refreshedAtMillis", now)
        }
        return jsonResponse(200, body)
    }

    private fun cancelResponse(request: RecordedRequest): MockResponse {
        if (!authorized(request)) return unauthorized()
        val requestId = runCatching { JSONObject(request.body.readUtf8()).optString("requestId") }
            .getOrNull()
            .orEmpty()
        if (requestId.isNotBlank()) cancelledRequestIds += requestId
        return jsonResponse(202, JSONObject().put("cancelled", requestId.isNotBlank()))
    }

    private fun respond(request: RecordedRequest): MockResponse {
        if (!authorized(request)) return unauthorized()
        val root = runCatching { JSONObject(request.body.readUtf8()) }.getOrNull()
            ?: return jsonResponse(400, errorJson("malformed_request"))
        val requestId = root.optString("requestId")
        val modelId = root.optString("modelId")
        if (requestId.isBlank() || modelId.isBlank()) {
            return jsonResponse(400, errorJson("invalid_request"))
        }
        if (root.optString("clientSchemaVersion") != CLIENT_SCHEMA_VERSION) {
            return jsonResponse(400, errorJson("unsupported_client_schema"))
        }
        if (containsForbiddenCategory(root)) {
            audit += auditRecord(root, requestId, modelId).copy(errorCode = "privacy_category_blocked")
            return jsonResponse(
                400,
                errorJson("privacy_category_blocked", quotaType = "privacy_policy")
            )
        }
        if (models.none { it.id == modelId && it.allowed }) {
            audit += auditRecord(root, requestId, modelId).copy(errorCode = "model_not_allowed")
            return jsonResponse(400, errorJson("model_not_allowed"))
        }

        val now = System.currentTimeMillis()
        val overQuota = synchronized(requestTimesMillis) {
            requestTimesMillis.removeExpired(now)
            val limit = quota.requestsPerMinute
            if (limit != null && requestTimesMillis.size >= limit) true
            else {
                requestTimesMillis.addLast(now)
                false
            }
        }
        if (overQuota) {
            audit += auditRecord(root, requestId, modelId).copy(errorCode = "quota_exceeded")
            return jsonResponse(
                429,
                errorJson(
                    code = "quota_exceeded",
                    retryAfter = 60,
                    quotaType = "requests_per_minute"
                )
            ).setHeader("Retry-After", "60")
        }

        val record = auditRecord(root, requestId, modelId)
        if (cancelledRequestIds.contains(requestId)) {
            audit += record.copy(errorCode = "cancelled")
            return jsonResponse(409, errorJson("cancelled"))
        }

        val response = synchronized(responseQueue) {
            if (responseQueue.isEmpty()) {
                FakeGatewayResponse.Final(AgentReport(summary = "Fake gateway response"))
            } else {
                responseQueue.removeFirst()
            }
        }
        audit += record.withModelResponse(response).copy(
            errorCode = (response as? FakeGatewayResponse.Error)?.code
        )
        return responseJson(response)
    }

    /** Audit model-selected tools without retaining their argument values. */
    private fun FakeGatewayAuditRecord.withModelResponse(
        response: FakeGatewayResponse
    ): FakeGatewayAuditRecord = when (response) {
        is FakeGatewayResponse.ToolCalls -> copy(
            toolNames = toolNames + response.calls.map { it.toolName },
            parameterHashes = parameterHashes + response.calls.map { call ->
                sha256(JSONObject(call.arguments).toString())
            }
        )
        else -> this
    }

    private fun auditRecord(root: JSONObject, requestId: String, modelId: String): FakeGatewayAuditRecord {
        val toolNames = mutableListOf<String>()
        val parameterHashes = mutableListOf<String>()
        val categories = mutableMapOf<String, Int>()
        val messages = root.optJSONArray("messages")
        if (messages != null) {
            for (index in 0 until messages.length()) {
                val message = messages.optJSONObject(index) ?: continue
                val toolResult = message.optJSONObject("toolResult")
                val category = toolResult?.optString("sensitivity").orEmpty()
                    .ifBlank { message.optString("dataCategory") }
                if (category.isNotBlank()) categories[category] = (categories[category] ?: 0) + 1
                val calls = message.optJSONArray("toolCalls") ?: continue
                for (callIndex in 0 until calls.length()) {
                    val call = calls.optJSONObject(callIndex) ?: continue
                    call.optString("name").takeIf { it.isNotBlank() }?.let(toolNames::add)
                    call.opt("arguments")?.takeUnless { it == JSONObject.NULL }
                        ?.let { parameterHashes += sha256(it.toString()) }
                }
            }
        }
        return FakeGatewayAuditRecord(
            requestId = requestId,
            modelId = modelId,
            toolNames = toolNames,
            parameterHashes = parameterHashes,
            dataCategoryCounts = categories
        )
    }

    private fun responseJson(response: FakeGatewayResponse): MockResponse = when (response) {
        is FakeGatewayResponse.ToolCalls -> jsonResponse(
            200,
            JSONObject().put("type", "tool_calls")
                .put("assistantContent", response.assistantContent)
                .putOptional("reasoningContent", response.reasoningContent)
                .put(
                    "toolCalls",
                    JSONArray().apply { response.calls.forEach { put(toolCallJson(it)) } }
                )
        )
        is FakeGatewayResponse.Final -> jsonResponse(
            200,
            JSONObject().put("type", "final")
                .putOptional("reasoningContent", response.reasoningContent)
                .put("report", JSONObject(AgentJsonCodec.encodeReport(response.report)))
        )
        is FakeGatewayResponse.Refusal -> jsonResponse(
            200,
            JSONObject().put("type", "refusal").put("reason", response.reason)
        )
        is FakeGatewayResponse.Error -> jsonResponse(
            response.statusCode,
            errorJson(response.code, response.retryAfterSeconds, response.quotaType)
        )
    }

    private fun authorized(request: RecordedRequest): Boolean =
        request.getHeader("Authorization") == "Bearer $accessToken"

    private fun unauthorized(): MockResponse = jsonResponse(401, errorJson("token_expired"))

    private fun errorJson(
        code: String,
        retryAfter: Long? = null,
        quotaType: String? = null
    ): JSONObject = JSONObject().put("error", JSONObject().apply {
        put("code", code)
        put("message", "Gateway request rejected.")
        retryAfter?.let { put("retryAfter", it) }
        quotaType?.let { put("quotaType", it) }
    })

    private fun accountJson(): JSONObject = JSONObject().apply {
        put("userId", account.userId)
        put("organizationId", account.organizationId)
        put("planId", account.planId)
        account.tokenExpiresAtMillis?.let { put("tokenExpiresAtMillis", it) }
    }

    private fun quotaJson(): JSONObject = JSONObject().apply {
        quota.requestsPerMinute?.let { put("requestsPerMinute", it) }
        quota.concurrentSessions?.let { put("concurrentSessions", it) }
        quota.tokensPerDay?.let { put("tokensPerDay", it) }
        quota.tokensPerMonth?.let { put("tokensPerMonth", it) }
        quota.costMicrosPerMonth?.let { put("costMicrosPerMonth", it) }
        quota.maxContextTokens?.let { put("maxContextTokens", it) }
        quota.maxOutputTokens?.let { put("maxOutputTokens", it) }
    }

    private fun modelJson(model: GatewayModel): JSONObject = JSONObject().apply {
        put("modelId", model.id)
        put("displayName", model.displayName)
        put("allowed", model.allowed)
        model.region?.let { put("region", it) }
        model.dataPolicy?.let { put("dataPolicy", it) }
        put("capabilities", JSONObject().apply {
            put("toolCalling", model.capabilities.toolCalling)
            put("parallelToolCalls", model.capabilities.parallelToolCalls)
            put("structuredOutput", model.capabilities.structuredOutput)
            put("streaming", model.capabilities.streaming)
            put("maxContextTokens", model.capabilities.maxContextTokens)
            put("maxOutputTokens", model.capabilities.maxOutputTokens)
        })
    }

    private fun toolCallJson(call: AgentToolCall): JSONObject = JSONObject().apply {
        put("id", call.toolCallId)
        put("name", call.toolName)
        put("arguments", JSONObject(call.arguments))
    }

    private fun containsForbiddenCategory(value: Any?): Boolean {
        when (value) {
            is JSONObject -> {
                val keys = value.keys()
                while (keys.hasNext()) {
                    val key = keys.next()
                    val child = value.opt(key)
                    val normalizedKey = key.lowercase().filter(Char::isLetterOrDigit)
                    if (normalizedKey in FORBIDDEN_KEYS) return true
                    if (normalizedKey in CATEGORY_KEYS &&
                        child?.toString()?.lowercase() in FORBIDDEN_CATEGORIES
                    ) return true
                    if (containsForbiddenCategory(child)) return true
                }
            }
            is JSONArray -> {
                for (index in 0 until value.length()) {
                    if (containsForbiddenCategory(value.opt(index))) return true
                }
            }
        }
        return false
    }

    private fun jsonResponse(statusCode: Int, body: JSONObject): MockResponse =
        MockResponse()
            .setResponseCode(statusCode)
            .setHeader("Content-Type", "application/json")
            .setBody(body.toString())

    private fun JSONObject.putOptional(key: String, value: Any?): JSONObject = apply {
        if (value != null) put(key, value)
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray())
        .joinToString("") { byte -> "%02x".format(byte) }

    private fun ArrayDeque<Long>.removeExpired(now: Long) {
        while (isNotEmpty() && first() <= now - 60_000L) removeFirst()
    }

    private companion object {
        const val CLIENT_SCHEMA_VERSION = "ai-23-gateway-v2"
        val FORBIDDEN_KEYS = setOf(
            "pcap", "pcapfile", "pcapdata", "packetbytes", "rawpayload",
            "credential", "credentials", "apikey", "providerkey", "secretkey"
        )
        val CATEGORY_KEYS = setOf("sensitivity", "datacategory", "category")
        val FORBIDDEN_CATEGORIES = setOf("payload", "credential", "credentials")
    }
}
