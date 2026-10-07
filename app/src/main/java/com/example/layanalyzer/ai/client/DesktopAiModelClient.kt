package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentPrivacyMode

/**
 * Configuration for a desktop or LAN-based model gateway.
 *
 * AI-25 requires device pairing with short-term tokens, TLS by default, and
 * clear user visibility into where data is being sent.
 */
data class DesktopModelConfiguration(
    val modelId: String,
    val gatewayBaseUrl: String,
    val deviceName: String? = null,
    val requireTls: Boolean = true
)

/**
 * Pairing token for desktop/LAN gateway authentication.
 *
 * AI-25: short-lived, device-specific tokens rather than long-lived API keys.
 * The user pairs the phone with the desktop once; subsequent sessions refresh
 * the token rather than re-pairing.
 */
data class DesktopPairingToken(
    val token: String,
    val deviceId: String,
    val expiresAtMillis: Long
) {
    fun isExpired(nowMillis: Long = System.currentTimeMillis()): Boolean =
        expiresAtMillis <= nowMillis
}

/**
 * Desktop/LAN AI model client using the AI-23 normalized protocol.
 *
 * AI-25 contract:
 * - Uses the same or compatible normalized protocol as AI-23 gateway
 * - Device pairing with short-term tokens
 * - TLS by default; plaintext connections require explicit warning and cannot
 *   be in Release default configuration
 * - Capability handshake, timeout, cancellation, and reconnection
 * - User knows data is leaving the phone and where it's going (device name)
 *
 * This reuses CloudAiModelClient's wire format but with desktop-specific
 * authentication and connection lifecycle.
 */
class DesktopAiModelClient(
    private val configuration: DesktopModelConfiguration,
    private val transport: AgentHttpTransport,
    private val pairingTokenProvider: () -> DesktopPairingToken?,
    private val onPairingExpired: () -> Unit = {},
    initialCapabilities: AiModelCapabilities = AiModelCapabilities.PHASE0,
    override val negotiateBeforeRun: Boolean = true,
    private val allowInsecureHttpForTests: Boolean = false
) : AiModelClient, AgentCapabilityNegotiator {

    private val delegate: CloudAiModelClient = CloudAiModelClient(
        gatewayBaseUrl = configuration.gatewayBaseUrl,
        transport = transport,
        providerId = "desktop",
        modelId = configuration.modelId,
        authTokenProvider = ::getPairingToken,
        byokSecretProvider = { null },
        initialCapabilities = initialCapabilities,
        negotiateBeforeRun = negotiateBeforeRun,
        responseEndpointPath = "v1/agent/respond",
        modelsEndpointPath = "v1/models",
        cancelEndpointPath = "v1/agent/cancel",
        clientSchemaVersion = CLIENT_SCHEMA_VERSION,
        allowInsecureHttpForTests = allowInsecureHttpForTests
    )

    override val id: String = "desktop:${configuration.modelId}"

    override val capabilities: AiModelCapabilities
        get() = delegate.capabilities

    override val oneShotFallback: Boolean
        get() = delegate.oneShotFallback

    /**
     * AI-25: a desktop/LAN model is still *off-device*, so it is treated exactly
     * like any other remote backend.
     *
     * [AgentPrivacyMode.LocalOnly] disables redaction entirely
     * ([com.example.layanalyzer.ai.privacy.AgentPrivacyPolicy.shouldRedact]
     * returns false), because nothing is supposed to leave the device in that
     * mode. Sending to a LAN peer under LocalOnly would therefore ship
     * *unredacted* capture data over the network. The delegate rejects LocalOnly
     * before any URL or transport work, and that guard is deliberately not
     * relaxed here.
     */
    override suspend fun respond(request: AgentModelRequest): AgentModelResponse {
        // AI-25: TLS enforcement. Plaintext is only reachable through the
        // explicit test switch, never through Release wiring.
        tlsError()?.let { return AgentModelResponse.Failure(it) }

        val response = delegate.respond(request)

        // AI-25: surface pairing revocation/expiry so the UI can re-pair.
        if (response is AgentModelResponse.Failure &&
            response.error.code == AgentErrorCode.MODEL_AUTH_FAILED
        ) {
            notifyPairingExpired()
        }

        return response
    }

    override fun cancel(requestId: String) {
        delegate.cancel(requestId)
    }

    override suspend fun negotiateCapabilities(): AgentError? {
        tlsError()?.let { return it }
        val error = delegate.negotiateCapabilities()
        if (error?.code == AgentErrorCode.MODEL_AUTH_FAILED) {
            notifyPairingExpired()
        }
        return error
    }

    private fun tlsError(): AgentError? {
        if (configuration.requireTls &&
            !allowInsecureHttpForTests &&
            !isSecureGatewayUrl(configuration.gatewayBaseUrl)
        ) {
            return AgentError(
                code = AgentErrorCode.MODEL_UNAVAILABLE,
                userMessage = "Desktop model requires a secure HTTPS connection.",
                retryable = false,
                details = mapOf("reason" to "tls_required")
            )
        }
        return null
    }

    /** Visible for contract tests; never includes the pairing token. */
    fun encodeRequest(request: AgentModelRequest): String = delegate.encodeRequest(request)

    private fun getPairingToken(): String? {
        val pairing = pairingTokenProvider() ?: return null
        if (pairing.isExpired()) {
            notifyPairingExpired()
            return null
        }
        return pairing.token
    }

    /**
     * Report a revoked or expired pairing exactly once per call.
     *
     * One request can detect the same dead pairing twice: [getPairingToken]
     * notices the local expiry while building the header, and the gateway then
     * answers 401 for the tokenless request. Both are the *same* event, so the
     * flag collapses them — otherwise a host that re-pairs or clears state in
     * this callback would be driven twice per request.
     */
    private fun notifyPairingExpired() {
        if (pairingExpiryReported.compareAndSet(false, true)) {
            onPairingExpired()
        }
    }

    private val pairingExpiryReported = java.util.concurrent.atomic.AtomicBoolean(false)

    companion object {
        /**
         * AI-25: desktop/LAN clients use the same normalized protocol as AI-23
         * production gateway, ensuring consistency across remote model types.
         */
        const val CLIENT_SCHEMA_VERSION = "ai-23-gateway-v2"
    }
}

/**
 * Store for desktop pairing tokens.
 *
 * AI-25: pairing tokens are short-lived and device-specific. They're stored
 * encrypted (like gateway sessions) but are managed separately since the
 * pairing flow is different from account login.
 */
interface DesktopPairingStore {
    fun getPairing(deviceId: String): DesktopPairingToken?

    fun savePairing(pairing: DesktopPairingToken): Result<Unit>

    fun clearPairing(deviceId: String)

    fun listPairedDevices(): List<String>
}
