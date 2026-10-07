package com.example.layanalyzer.ai.agent

import android.content.Context
import com.example.layanalyzer.ai.client.GatewayAccount
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject

/** Short-lived user session held by Android; the access token is never in settings. */
class GatewayAuthSession(
    val accessToken: String,
    val userId: String,
    val organizationId: String? = null,
    val planId: String? = null,
    val expiresAtMillis: Long,
    val sessionId: String? = null
) {
    init {
        require(accessToken.isNotBlank()) { "Gateway access token must not be blank." }
        require(userId.isNotBlank()) { "Gateway user id must not be blank." }
        require(expiresAtMillis > 0L) { "Gateway access token must have an expiry." }
    }

    fun isExpired(nowMillis: Long = System.currentTimeMillis()): Boolean =
        expiresAtMillis <= nowMillis

    fun account(): GatewayAccount = GatewayAccount(
        userId = userId,
        organizationId = organizationId,
        planId = planId,
        tokenExpiresAtMillis = expiresAtMillis
    )

    override fun toString(): String =
        "GatewayAuthSession(userId=$userId, organizationId=$organizationId, " +
            "expiresAtMillis=$expiresAtMillis, sessionId=$sessionId, accessToken=<redacted>)"
}

/** Storage boundary for login/logout code supplied by the host application. */
interface GatewaySessionStore {
    val session: GatewayAuthSession?

    val sessionFlow: StateFlow<GatewayAuthSession?>

    /** Returns null for a missing, expired, or revoked local session. */
    fun accessToken(): String?

    fun save(session: GatewayAuthSession): Result<Unit>

    fun clear()
}

/** In-memory implementation for JVM tests and embedding applications. */
class InMemoryGatewaySessionStore(
    initialSession: GatewayAuthSession? = null,
    private val clock: () -> Long = { System.currentTimeMillis() }
) : GatewaySessionStore {
    private val state = MutableStateFlow(initialSession)

    override val session: GatewayAuthSession?
        get() = state.value

    override val sessionFlow: StateFlow<GatewayAuthSession?> = state.asStateFlow()

    override fun accessToken(): String? {
        val current = state.value ?: return null
        if (current.isExpired(clock())) {
            clear()
            return null
        }
        return current.accessToken
    }

    override fun save(session: GatewayAuthSession): Result<Unit> {
        if (session.isExpired(clock())) {
            return Result.failure(IllegalArgumentException("Gateway access token is expired."))
        }
        state.value = session
        return Result.success(Unit)
    }

    override fun clear() {
        state.value = null
    }
}

/**
 * Encrypted session storage. The ciphertext is below noBackupFilesDir and the
 * token is only decrypted when the gateway adapter asks for it.
 */
class AndroidKeystoreGatewaySessionStore(
    context: Context,
    keyAlias: String = DEFAULT_KEY_ALIAS,
    private val clock: () -> Long = { System.currentTimeMillis() }
) : GatewaySessionStore {
    private val secretStore = AndroidKeystoreSecretStore(context, keyAlias)
    private val state = MutableStateFlow(load())

    override val session: GatewayAuthSession?
        get() = state.value

    override val sessionFlow: StateFlow<GatewayAuthSession?> = state.asStateFlow()

    override fun accessToken(): String? {
        val current = state.value ?: return null
        if (current.isExpired(clock())) {
            clear()
            return null
        }
        return current.accessToken
    }

    override fun save(session: GatewayAuthSession): Result<Unit> {
        if (session.isExpired(clock())) {
            return Result.failure(IllegalArgumentException("Gateway access token is expired."))
        }
        val encoded = JSONObject().apply {
            put("accessToken", session.accessToken)
            put("userId", session.userId)
            put("organizationId", session.organizationId)
            put("planId", session.planId)
            put("expiresAtMillis", session.expiresAtMillis)
            put("sessionId", session.sessionId)
        }.toString()
        return secretStore.save(encoded).also { result ->
            if (result.isSuccess) state.value = session
        }
    }

    override fun clear() {
        secretStore.clear()
        state.value = null
    }

    private fun load(): GatewayAuthSession? = runCatching {
        if (!secretStore.hasSecret) return null
        val json = JSONObject(secretStore.read() ?: return null)
        GatewayAuthSession(
            accessToken = json.getString("accessToken"),
            userId = json.getString("userId"),
            organizationId = json.optString("organizationId").ifBlank { null },
            planId = json.optString("planId").ifBlank { null },
            expiresAtMillis = json.getLong("expiresAtMillis"),
            sessionId = json.optString("sessionId").ifBlank { null }
        ).takeUnless { it.isExpired(clock()) }
    }.getOrNull()

    private companion object {
        const val DEFAULT_KEY_ALIAS = "layeranalyzer.gateway.session.v1"
    }
}

typealias GatewayAuthStore = GatewaySessionStore
