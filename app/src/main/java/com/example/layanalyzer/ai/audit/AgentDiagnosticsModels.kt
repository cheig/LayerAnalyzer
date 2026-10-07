package com.example.layanalyzer.ai.audit

import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode

/** Events written while an Agent run is in progress. */
enum class AgentDiagnosticsEventType {
    RunStarted,
    Configuration,
    SnapshotReady,
    SnapshotFailed,
    AnalysisBootstrap,
    ModelRequestStarted,
    ModelResponse,
    ToolStarted,
    ToolFinished,
    PlanDeclared,
    PlanDeviation,
    Validation,
    /** A phase transition the state machine refused from a live (non-terminal) phase. */
    PhaseTransition,
    RunMetrics,
    RunFinished,
    RunAbandoned
}

/** A bounded, redacted exception summary safe to include in a local export. */
data class AgentDiagnosticsException(
    val type: String,
    val message: String? = null,
    val stack: String? = null,
    val causes: List<String> = emptyList()
)

/** Technical failure context kept out of the user-facing [AgentError]. */
data class AgentDiagnosticsFailure(
    val boundary: String,
    val errorCode: AgentErrorCode? = null,
    val retryable: Boolean? = null,
    val reason: String? = null,
    val providerStatus: Int? = null,
    val providerCode: String? = null,
    val providerType: String? = null,
    val providerMessage: String? = null,
    /** connect/write/headers/body_read/decode; never contains an exception body. */
    val failureStage: String? = null,
    /** dns/connect/tls/reset/timeout/offline/unknown. */
    val networkFailureKind: String? = null,
    val bytesReceived: Long? = null,
    val responseLimitBytes: Long? = null,
    val responsePreview: String? = null,
    val exception: AgentDiagnosticsException? = null
)

/** One redacted event in the append-only diagnostics stream. */
data class AgentDiagnosticsEvent(
    val runId: String,
    val sessionId: String,
    val sequence: Long,
    val timestampMillis: Long,
    val type: AgentDiagnosticsEventType,
    val conversationId: String = "",
    val captureFingerprint: String = "",
    val modelId: String = "",
    val promptVersion: String = "",
    val playbookVersion: String? = null,
    val phase: String? = null,
    val turn: Int? = null,
    val step: Int? = null,
    val toolName: String? = null,
    val argumentsHash: String? = null,
    val durationMillis: Long? = null,
    val status: String? = null,
    val failure: AgentDiagnosticsFailure? = null,
    val attributes: Map<String, String> = emptyMap()
)

/** Convert a normalized Agent error into export-safe diagnostic context. */
fun AgentError.toDiagnosticsFailure(boundary: String): AgentDiagnosticsFailure =
    AgentDiagnosticsFailure(
        boundary = boundary,
        errorCode = code,
        retryable = retryable,
        reason = diagnosticsReason(details),
        providerStatus = details.firstInt("httpStatus", "statusCode"),
        providerCode = details.firstText("remoteCode", "providerCode"),
        providerType = details.firstText("remoteType", "providerType"),
        providerMessage = details.firstText("remoteMessage", "providerMessage"),
        failureStage = details.firstText("failureStage"),
        networkFailureKind = details.firstText("networkFailureKind"),
        bytesReceived = details.firstLong("bytesReceived"),
        responseLimitBytes = details.firstLong("responseLimitBytes"),
        // Raw or even bounded provider response text is intentionally not
        // copied into diagnostics.  The legacy field remains nullable solely
        // so old exported records can still be decoded.
        responsePreview = null
    )

/** Convert an unexpected non-fatal exception into export-safe diagnostic context. */
fun Throwable.toDiagnosticsFailure(
    boundary: String,
    errorCode: AgentErrorCode = AgentErrorCode.INTERNAL_ERROR,
    retryable: Boolean = false
): AgentDiagnosticsFailure = AgentDiagnosticsFailure(
    boundary = boundary,
    errorCode = errorCode,
    retryable = retryable,
    reason = "unexpected_exception",
    exception = toDiagnosticsException()
)

/** Exceptions that must retain structured concurrency or process safety. */
fun Throwable.isAgentFatal(): Boolean =
    this is kotlinx.coroutines.CancellationException ||
        this is VirtualMachineError ||
        this is ThreadDeath ||
        this is LinkageError

private fun Throwable.toDiagnosticsException(): AgentDiagnosticsException {
    val chain = buildList {
        var current: Throwable? = cause
        var depth = 0
        while (current != null && depth < MAX_CAUSE_DEPTH) {
            add(current.javaClass.simpleName.ifBlank { "UnknownThrowable" })
            current = current.cause
            depth += 1
        }
    }
    val frames = stackTrace
        .take(MAX_STACK_FRAMES)
        .joinToString("\n") { frame ->
            val file = frame.fileName ?: "?"
            "${frame.className.substringAfterLast('.')}.${frame.methodName}($file:${frame.lineNumber})"
        }
        .take(MAX_STACK_CHARS)
        .ifBlank { null }
    return AgentDiagnosticsException(
        type = javaClass.name.substringAfterLast('.').take(MAX_TEXT_CHARS),
        message = sanitizeDiagnosticsText(message),
        stack = frames,
        causes = chain
    )
}

private fun diagnosticsReason(details: Map<String, Any?>): String? =
    details.entries
        .firstOrNull { it.key in SAFE_REASON_KEYS }
        ?.value
        ?.toString()
        ?.let(::sanitizeDiagnosticsText)

private fun Map<String, Any?>.firstText(vararg keys: String): String? =
    keys.asSequence()
        .mapNotNull { key ->
            get(key)
                ?.takeUnless { it == org.json.JSONObject.NULL }
                ?.toString()
                ?.takeIf { it.isNotBlank() }
        }
        .firstOrNull()

private fun Map<String, Any?>.firstInt(vararg keys: String): Int? =
    keys.asSequence()
        .mapNotNull { key ->
            when (val value = get(key)) {
                is Number -> value.toInt()
                is String -> value.toIntOrNull()
                else -> null
            }
        }
        .firstOrNull()

private fun Map<String, Any?>.firstLong(vararg keys: String): Long? =
    keys.asSequence()
        .mapNotNull { key ->
            when (val value = get(key)) {
                is Number -> value.toLong()
                is String -> value.toLongOrNull()
                else -> null
            }
        }
        .firstOrNull()

/** Remove common secret/identity forms before technical text leaves the device. */
internal fun sanitizeDiagnosticsText(value: String?, maxLength: Int = MAX_TEXT_CHARS): String? {
    if (value.isNullOrBlank()) return null
    var sanitized = value
        .replace(
            Regex("(?i)bearer\\s+[A-Za-z0-9._~+/=-]+"),
            "Bearer <redacted>"
        )
        .replace(
            Regex("(?i)(authorization|api[-_ ]?key|token|secret|password)\\s*[:=]\\s*[^,\\s]+"),
            "${'$'}1=<redacted>"
        )
        .replace(
            Regex("(?i)(imsi|imei|msisdn|call[-_ ]?id)\\s*[:=]\\s*[^,\\s]+"),
            "${'$'}1=<redacted>"
        )
        .replace(Regex("(?i)\\b(sips?|tel):[^\\s\"'}>,;]+"), "<uri>")
        .replace(Regex("(?<![A-Fa-f0-9:.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\d.])"), "<ip>")
        .replace(
            Regex("(?i)(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Fa-f0-9:])"),
            "<ip>"
        )
        .replace(Regex("(?<![A-Za-z0-9])\\+?\\d[\\d ()-]{6,}\\d(?![A-Za-z0-9])"), "<number>")
        .replace(Regex("https?://[^\\s]+"), "<url>")
        .replace(Regex("[\\r\\n\\t]+"), " ")
        .trim()
    return sanitized.take(maxLength).ifBlank { null }
}

internal const val MAX_TEXT_CHARS = 512
private const val MAX_STACK_FRAMES = 16
private const val MAX_STACK_CHARS = 4_096
private const val MAX_CAUSE_DEPTH = 4
private val SAFE_REASON_KEYS = setOf(
    "reason",
    "field",
    "contract",
    "providerId",
    "providerCode",
    "statusCode",
    "responseType",
    "boundary"
)
