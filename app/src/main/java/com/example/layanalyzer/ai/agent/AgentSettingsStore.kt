package com.example.layanalyzer.ai.agent

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.example.layanalyzer.ai.client.MockModelScriptLibrary
import com.example.layanalyzer.model.AgentPrivacyMode
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

/** Wire protocol used by a user-configured direct provider. */
enum class AgentApiType(val storageKey: String) {
    OPENAI_CHAT_COMPLETIONS("openai_chat_completions"),
    OPENAI_RESPONSES("openai_responses"),
    ANTHROPIC_API("anthropic_api");

    companion object {
        fun fromStorage(raw: String?): AgentApiType? = when (raw?.trim()?.lowercase()) {
            null, "", "openai_chat_completions", "openai_chat_completion",
            "openai_compatible", "chat_completions" -> OPENAI_CHAT_COMPLETIONS
            "openai_responses", "openai_response", "responses" -> OPENAI_RESPONSES
            "anthropic_api", "anthropic_messages", "anthropic" -> ANTHROPIC_API
            else -> null
        }

        // Compatibility aliases for callers that use the provider terminology.
        val OPENAI_COMPATIBLE: AgentApiType
            get() = OPENAI_CHAT_COMPLETIONS
        val OPENAI_RESPONSE: AgentApiType
            get() = OPENAI_RESPONSES
        val ANTHROPIC: AgentApiType
            get() = ANTHROPIC_API
        val ANTHROPIC_MESSAGES: AgentApiType
            get() = ANTHROPIC_API
    }
}

/**
 * How hard a reasoning-capable model should think.
 *
 * [UNSPECIFIED] means "do not send a provider field" so existing models keep
 * their current behaviour. The adapters then encode a configured value in the
 * shape each API actually accepts.
 */
enum class AgentReasoningEffort(val storageKey: String) {
    UNSPECIFIED("unspecified"),
    NONE("none"),
    MINIMAL("minimal"),
    LOW("low"),
    MEDIUM("medium"),
    HIGH("high"),
    XHIGH("xhigh");

    val wireValue: String get() = storageKey

    val isConfigured: Boolean get() = this != UNSPECIFIED

    /**
     * Anthropic charges thinking against `max_tokens` via `budget_tokens`.
     * `none` disables thinking instead of sending a zero budget.
     */
    fun anthropicBudgetTokens(): Int? = when (this) {
        UNSPECIFIED, NONE -> null
        MINIMAL -> ANTHROPIC_BUDGET_MINIMAL
        LOW -> ANTHROPIC_BUDGET_LOW
        MEDIUM -> ANTHROPIC_BUDGET_MEDIUM
        HIGH -> ANTHROPIC_BUDGET_HIGH
        XHIGH -> ANTHROPIC_BUDGET_XHIGH
    }

    companion object {
        const val REASONING_CONTEXT_ALL_TURNS = "all_turns"
        const val ANTHROPIC_BUDGET_MINIMAL = 1_024
        const val ANTHROPIC_BUDGET_LOW = 4_096
        const val ANTHROPIC_BUDGET_MEDIUM = 10_240
        const val ANTHROPIC_BUDGET_HIGH = 16_384
        const val ANTHROPIC_BUDGET_XHIGH = 32_768

        fun fromStorage(raw: String?): AgentReasoningEffort? = when (raw?.trim()?.lowercase()) {
            null, "" -> UNSPECIFIED
            "unspecified", "default", "auto" -> UNSPECIFIED
            "none", "off", "disabled" -> NONE
            "minimal", "min" -> MINIMAL
            "low" -> LOW
            "medium" -> MEDIUM
            "high" -> HIGH
            "xhigh", "extra_high", "extra-high", "extrahigh" -> XHIGH
            else -> null
        }
    }
}

/** Structured-output mode used by OpenAI-compatible Chat Completions providers. */
enum class AgentChatResponseFormat(val storageKey: String) {
    /** Compatibility mode: describe the schema in the prompt only. */
    PROMPT_ONLY("prompt_only"),
    /** Ask the provider to return a valid JSON object without enforcing a schema. */
    JSON_OBJECT("json_object"),
    /** Ask the provider to enforce the request's native JSON Schema. */
    JSON_SCHEMA("json_schema");

    companion object {
        /**
         * Absent storage resolves to [JSON_OBJECT], not to prompt-only.
         *
         * Providers saved before this setting existed carry no value, and
         * leaving them on prompt-only would keep exactly the configuration that
         * lets a model answer with prose around hand-written JSON.  An explicit
         * `prompt_only` on record is still honoured.
         */
        fun fromStorage(raw: String?): AgentChatResponseFormat? = when (
            raw?.trim()?.lowercase()
        ) {
            null, "" -> JSON_OBJECT
            "prompt_only", "prompt" -> PROMPT_ONLY
            "json_object", "json" -> JSON_OBJECT
            "json_schema", "schema" -> JSON_SCHEMA
            else -> null
        }
    }
}

/** A model exposed by a user-configured provider. */
data class AgentModelConfig(
    val id: String,
    /**
     * Optional human-readable label. Empty means "reuse [id]" everywhere: the
     * settings form leaves the field blank, [displayName] resolves the fallback
     * for the UI, and the request path only ever reads [id]. Stays empty through
     * [normalized] on purpose — backfilling [id] here would make the editor show
     * a value the user never typed the next time the provider is opened.
     */
    val name: String = "",
    /** Optional advanced override; null means use adapter/model knowledge. */
    val contextLimitTokens: Int? = null,
    /** Optional advanced override; null means use adapter/model knowledge. */
    val outputLimitTokens: Int? = null,
    /**
     * Optional thinking intensity. [AgentReasoningEffort.UNSPECIFIED] leaves the
     * request unchanged so models that do not support reasoning stay valid.
     */
    val reasoningEffort: AgentReasoningEffort = AgentReasoningEffort.UNSPECIFIED
) {
    /** The label to render for this model; falls back to [id] when unset. */
    val displayName: String get() = name.trim().ifBlank { id.trim() }

    fun normalized(): AgentModelConfig {
        require(contextLimitTokens == null ||
            contextLimitTokens in MIN_CONTEXT_LIMIT_TOKENS..MAX_CONTEXT_LIMIT_TOKENS
        ) { "contextLimitTokens is outside the supported range." }
        require(outputLimitTokens == null ||
            outputLimitTokens in MIN_OUTPUT_LIMIT_TOKENS..MAX_OUTPUT_LIMIT_TOKENS
        ) { "outputLimitTokens is outside the supported range." }
        return copy(
            id = id.trim(),
            name = name.trim()
        )
    }

    companion object {
        const val MIN_CONTEXT_LIMIT_TOKENS = 4_096
        const val MAX_CONTEXT_LIMIT_TOKENS = 2_000_000
        const val MIN_OUTPUT_LIMIT_TOKENS = 512
        const val MAX_OUTPUT_LIMIT_TOKENS = 2_000_000
    }
}

/** Non-secret configuration for one AI provider. */
data class AgentProviderConfig(
    /** Stable local identifier. It is also used to scope the Keystore secret. */
    val id: String,
    val name: String = id,
    val baseUrl: String = "",
    val models: List<AgentModelConfig> = emptyList(),
    /** Presence bit only; the API key itself never enters this data class. */
    val apiKeyConfigured: Boolean = false,
    /** Null means the legacy single-provider Keystore slot. */
    val secretKeyAlias: String? = null,
    val apiType: AgentApiType = AgentApiType.OPENAI_CHAT_COMPLETIONS,
    /**
     * Used only when [apiType] is Chat Completions.
     *
     * Defaults to [AgentChatResponseFormat.JSON_OBJECT] rather than prompt-only:
     * describing the schema in the prompt leaves the provider free to answer
     * with prose wrapped around a hand-written object, and a single missing
     * quote in a few thousand characters then discards the whole report.
     * `json_object` is the widely supported floor — it costs nothing on
     * providers that ignore it and prevents that failure on the ones that
     * honour it.  Providers with real schema support can be raised to
     * [AgentChatResponseFormat.JSON_SCHEMA] per provider.
     */
    val chatResponseFormat: AgentChatResponseFormat = AgentChatResponseFormat.JSON_OBJECT
) {
    fun normalized(): AgentProviderConfig {
        val normalizedId = id.trim()
        return copy(
            id = normalizedId,
            name = name.trim().ifBlank { normalizedId },
            baseUrl = baseUrl.trim().trimEnd('/'),
            models = models
                .map(AgentModelConfig::normalized)
                .filter { it.id.isNotBlank() }
                .distinctBy { it.id },
            secretKeyAlias = secretKeyAlias?.trim()?.ifBlank { null }
        )
    }
}

/** The settings needed to choose and describe one Agent model session. */
data class AgentSettings(
    val providerId: String = LOCAL_PROVIDER_ID,
    val modelId: String = MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS,
    val gatewayBaseUrl: String = "",
    val privacyMode: AgentPrivacyMode = AgentPrivacyMode.RedactedMetadata,
    val firstUseConsentVersion: String? = null,
    val requestPreviewEnabled: Boolean = true,
    /** This is only a presence bit. The secret itself never lives here. */
    val byokConfigured: Boolean = false,
    /** Additional model attempts after a retryable remote failure. */
    val maxModelRetries: Int = AgentPolicy.DEFAULT_MAX_MODEL_RETRIES,
    /**
     * Wall-clock ceiling of one remote model request, in seconds.
     *
     * Independent of tool-step timeouts so slow reasoning models keep working;
     * [AgentPolicy.MAX_MODEL_REQUEST_TIMEOUT_MILLIS] bounds what users may pick.
     */
    val maxModelRequestTimeoutSeconds: Int =
        (AgentPolicy.DEFAULT_MAX_MODEL_REQUEST_TIMEOUT_MILLIS / 1000L).toInt(),
    /** All configured providers. The active provider/model remain projected above. */
    val providers: List<AgentProviderConfig> = emptyList(),
    /** Debug-only continuous capture of raw provider response bodies. */
    val rawResponseCaptureEnabled: Boolean = false
) {
    /** A cloud request is possible only when provider, model and endpoint are present. */
    val isCloudConfigured: Boolean
        get() = providerId != LOCAL_PROVIDER_ID &&
            modelId.isNotBlank() &&
            gatewayBaseUrl.isNotBlank()

    /** Any non-default remote field means the user intended to call a real model. */
    val hasRemoteConfiguration: Boolean
        get() = providerId != LOCAL_PROVIDER_ID ||
            gatewayBaseUrl.isNotBlank() ||
            byokConfigured

    /**
     * Keep the free-form configuration forgiving without silently selecting the
     * offline demo. Entering an API URL while leaving the default `local`
     * provider is treated as an OpenAI-compatible BYOK endpoint.
     */
    fun normalized(): AgentSettings {
        val normalizedUrl = gatewayBaseUrl.trim().trimEnd('/')
        val requestedProvider = providerId.trim()
        val normalizedProvider = when {
            normalizedUrl.isNotBlank() &&
                (requestedProvider.isBlank() || requestedProvider == LOCAL_PROVIDER_ID) ->
                OPENAI_COMPATIBLE_PROVIDER_ID
            requestedProvider.isBlank() -> LOCAL_PROVIDER_ID
            else -> requestedProvider
        }
        val requestedModel = modelId.trim()
        val normalizedProviders = providers
            .map(AgentProviderConfig::normalized)
            .filter { it.id.isNotBlank() }
            .distinctBy { it.id }
            .toMutableList()

        if (normalizedProviders.isEmpty()) {
            normalizedProviders += AgentProviderConfig(
                id = normalizedProvider,
                name = normalizedProvider,
                baseUrl = normalizedUrl,
                models = listOf(
                    AgentModelConfig(
                        id = requestedModel,
                        name = requestedModel
                    )
                ).filter { it.id.isNotBlank() },
                apiKeyConfigured = byokConfigured
            )
        }

        val activeProvider = normalizedProviders.firstOrNull { it.id == normalizedProvider }
            ?: normalizedProviders.first()
        val activeModel = activeProvider.models.firstOrNull { it.id == requestedModel }
            ?: activeProvider.models.firstOrNull()
        val resolvedModelId = activeModel?.id ?: requestedModel
        return copy(
            providerId = activeProvider.id,
            modelId = resolvedModelId,
            gatewayBaseUrl = activeProvider.baseUrl.ifBlank {
                if (activeProvider.id == normalizedProvider) normalizedUrl else ""
            },
            byokConfigured = activeProvider.apiKeyConfigured,
            maxModelRetries = maxModelRetries.coerceIn(0, AgentPolicy.MAX_MODEL_RETRIES),
            maxModelRequestTimeoutSeconds = maxModelRequestTimeoutSeconds.coerceIn(
                MIN_MODEL_REQUEST_TIMEOUT_SECONDS,
                (AgentPolicy.MAX_MODEL_REQUEST_TIMEOUT_MILLIS / 1000L).toInt()
            ),
            providers = normalizedProviders
        )
    }

    /** The active provider after applying legacy/default compatibility rules. */
    val activeProvider: AgentProviderConfig?
        get() = providers.firstOrNull { it.id == providerId }

    /** The active model after applying legacy/default compatibility rules. */
    val activeModel: AgentModelConfig?
        get() = activeProvider?.models?.firstOrNull { it.id == modelId }

    companion object {
        const val LOCAL_PROVIDER_ID = "local"
        const val GATEWAY_PROVIDER_ID = "gateway"
        const val OPENAI_COMPATIBLE_PROVIDER_ID = "openai-compatible"
        const val MIN_MODEL_REQUEST_TIMEOUT_SECONDS = 30
    }
}

/** Versioned privacy notice used to decide whether a cloud call needs consent. */
object AgentConsent {
    const val CURRENT_VERSION = "ai-23-gateway-policy-v1"

    fun isAccepted(settings: AgentSettings): Boolean =
        settings.firstUseConsentVersion == CURRENT_VERSION

    fun requiresConsent(settings: AgentSettings): Boolean =
        settings.isCloudConfigured &&
            settings.privacyMode != AgentPrivacyMode.LocalOnly &&
            !isAccepted(settings)
}

/** Restricts interactive analysis to the two metadata modes exposed by the composer. */
internal fun AgentPrivacyMode.selectableMetadataMode(): AgentPrivacyMode = when (this) {
    AgentPrivacyMode.UnredactedMetadata -> AgentPrivacyMode.UnredactedMetadata
    else -> AgentPrivacyMode.RedactedMetadata
}

/** Maps persisted legacy modes that are no longer user-selectable to a safe default. */
internal fun storedPrivacyMode(raw: String?, fallback: AgentPrivacyMode): AgentPrivacyMode {
    val parsed = raw?.let { value ->
        runCatching { AgentPrivacyMode.valueOf(value) }.getOrNull()
    } ?: fallback
    return parsed.selectableMetadataMode()
}

/**
 * Settings boundary used by the Agent and UI.
 *
 * The default properties preserve the small Phase 0 surface for tests and
 * callers that still provide a fixed Mock configuration. Implementations that
 * support editing should expose [settingsFlow] and [update].
 */
interface AgentSettingsStore {
    val modelScriptId: String
        get() = MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS

    val privacyMode: AgentPrivacyMode
        get() = AgentPrivacyMode.RedactedMetadata

    val providerId: String
        get() = AgentSettings.LOCAL_PROVIDER_ID

    val modelId: String
        get() = modelScriptId

    val gatewayBaseUrl: String
        get() = ""

    val firstUseConsentVersion: String?
        get() = null

    val requestPreviewEnabled: Boolean
        get() = true

    val byokConfigured: Boolean
        get() = false

    val maxModelRetries: Int
        get() = AgentPolicy.DEFAULT_MAX_MODEL_RETRIES

    val maxModelRequestTimeoutSeconds: Int
        get() = (AgentPolicy.DEFAULT_MAX_MODEL_REQUEST_TIMEOUT_MILLIS / 1000L).toInt()

    val providers: List<AgentProviderConfig>
        get() = emptyList()

    val rawResponseCaptureEnabled: Boolean
        get() = false

    val settings: AgentSettings
        get() = AgentSettings(
            providerId = providerId,
            modelId = modelId,
            gatewayBaseUrl = gatewayBaseUrl,
            privacyMode = privacyMode,
            firstUseConsentVersion = firstUseConsentVersion,
            requestPreviewEnabled = requestPreviewEnabled,
            byokConfigured = byokConfigured,
            maxModelRetries = maxModelRetries,
            maxModelRequestTimeoutSeconds = maxModelRequestTimeoutSeconds,
            providers = providers,
            rawResponseCaptureEnabled = rawResponseCaptureEnabled
        )

    /** Non-null for stores that can publish changes to an already-created UI. */
    val settingsFlow: StateFlow<AgentSettings>?
        get() = null
}

/** Mutable extension used by the configuration screen and consent flow. */
interface MutableAgentSettingsStore : AgentSettingsStore {
    fun update(settings: AgentSettings)

    fun update(transform: (AgentSettings) -> AgentSettings) {
        update(transform(settings))
    }

    fun acceptCurrentConsent() {
        update { it.copy(firstUseConsentVersion = AgentConsent.CURRENT_VERSION) }
    }

    fun clearConsent() {
        update { it.copy(firstUseConsentVersion = null) }
    }
}

/**
 * Fixed offline defaults retained for unit tests and for a clean install.
 * Selecting a gateway is an explicit configuration action; no production key
 * or production endpoint is embedded in the APK.
 */
data class DefaultAgentSettingsStore(
    override val modelScriptId: String = MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS,
    override val privacyMode: AgentPrivacyMode = AgentPrivacyMode.RedactedMetadata,
    override val providerId: String = AgentSettings.LOCAL_PROVIDER_ID,
    override val modelId: String = modelScriptId,
    override val gatewayBaseUrl: String = "",
    override val firstUseConsentVersion: String? = null,
    override val requestPreviewEnabled: Boolean = true,
    override val byokConfigured: Boolean = false,
    override val maxModelRetries: Int = AgentPolicy.DEFAULT_MAX_MODEL_RETRIES,
    override val maxModelRequestTimeoutSeconds: Int =
        (AgentPolicy.DEFAULT_MAX_MODEL_REQUEST_TIMEOUT_MILLIS / 1000L).toInt(),
    override val providers: List<AgentProviderConfig> = emptyList(),
    override val rawResponseCaptureEnabled: Boolean = false
) : AgentSettingsStore

/** SharedPreferences-backed configuration. Secrets are intentionally absent. */
class SharedPreferencesAgentSettingsStore private constructor(
    private val preferences: SharedPreferences,
    private val defaults: AgentSettings,
    @Suppress("UNUSED_PARAMETER") marker: Unit
) : MutableAgentSettingsStore {
    constructor(context: Context, preferencesName: String = PREFERENCES_NAME) : this(
        preferences = context.getSharedPreferences(preferencesName, Context.MODE_PRIVATE),
        defaults = AgentSettings(),
        marker = Unit
    )

    constructor(
        preferences: SharedPreferences,
        defaults: AgentSettings = AgentSettings()
    ) : this(preferences, defaults, Unit)

    private val state = MutableStateFlow(load())

    override val modelScriptId: String
        get() = state.value.modelId
    override val privacyMode: AgentPrivacyMode
        get() = state.value.privacyMode
    override val providerId: String
        get() = state.value.providerId
    override val modelId: String
        get() = state.value.modelId
    override val gatewayBaseUrl: String
        get() = state.value.gatewayBaseUrl
    override val firstUseConsentVersion: String?
        get() = state.value.firstUseConsentVersion
    override val requestPreviewEnabled: Boolean
        get() = state.value.requestPreviewEnabled
    override val byokConfigured: Boolean
        get() = state.value.byokConfigured
    override val maxModelRetries: Int
        get() = state.value.maxModelRetries
    override val maxModelRequestTimeoutSeconds: Int
        get() = state.value.maxModelRequestTimeoutSeconds
    override val providers: List<AgentProviderConfig>
        get() = state.value.providers
    override val rawResponseCaptureEnabled: Boolean
        get() = state.value.rawResponseCaptureEnabled
    override val settings: AgentSettings
        get() = state.value
    override val settingsFlow: StateFlow<AgentSettings> = state.asStateFlow()

    override fun update(settings: AgentSettings) {
        val normalized = settings.normalized().let { current ->
            current.copy(privacyMode = current.privacyMode.selectableMetadataMode())
        }
        preferences.edit()
            .putString(KEY_PROVIDER_ID, normalized.providerId)
            .putString(KEY_MODEL_ID, normalized.modelId)
            .putString(KEY_GATEWAY_BASE_URL, normalized.gatewayBaseUrl)
            .putString(KEY_PRIVACY_MODE, normalized.privacyMode.name)
            .putString(KEY_CONSENT_VERSION, normalized.firstUseConsentVersion)
            .putBoolean(KEY_PREVIEW_ENABLED, normalized.requestPreviewEnabled)
            .putBoolean(KEY_BYOK_CONFIGURED, normalized.byokConfigured)
            .putInt(KEY_MAX_MODEL_RETRIES, normalized.maxModelRetries)
            .putInt(
                KEY_MAX_MODEL_REQUEST_TIMEOUT_SECONDS,
                normalized.maxModelRequestTimeoutSeconds
            )
            .putString(KEY_PROVIDERS, AgentProviderConfigCodec.encode(normalized.providers))
            .putBoolean(KEY_RAW_RESPONSE_CAPTURE_ENABLED, normalized.rawResponseCaptureEnabled)
            .apply()
        state.value = normalized
    }

    fun setByokConfigured(configured: Boolean) {
        update { it.copy(byokConfigured = configured) }
    }

    private fun load(): AgentSettings {
        val rawProviders = preferences.getString(KEY_PROVIDERS, null)
        val decodedProviders = AgentProviderConfigCodec.decode(rawProviders) { warning ->
            Log.w(LOG_TAG, warning)
        }
        // If a stored provider envelope exists but every entry is rejected,
        // do not reconstruct its legacy endpoint as OpenAI Chat Completions.
        val rejectedStoredProviders = !rawProviders.isNullOrBlank() && decodedProviders.isEmpty()
        return AgentSettings(
            providerId = if (rejectedStoredProviders) defaults.providerId else {
                preferences.getString(KEY_PROVIDER_ID, defaults.providerId) ?: defaults.providerId
            },
            modelId = if (rejectedStoredProviders) defaults.modelId else {
                preferences.getString(KEY_MODEL_ID, defaults.modelId) ?: defaults.modelId
            },
            gatewayBaseUrl = if (rejectedStoredProviders) defaults.gatewayBaseUrl else {
                preferences.getString(KEY_GATEWAY_BASE_URL, defaults.gatewayBaseUrl)
                    ?: defaults.gatewayBaseUrl
            },
            privacyMode = storedPrivacyMode(
                preferences.getString(KEY_PRIVACY_MODE, null),
                defaults.privacyMode
            ),
            firstUseConsentVersion = preferences.getString(
                KEY_CONSENT_VERSION,
                defaults.firstUseConsentVersion
            ),
            requestPreviewEnabled = preferences.getBoolean(
                KEY_PREVIEW_ENABLED,
                defaults.requestPreviewEnabled
            ),
            byokConfigured = if (rejectedStoredProviders) defaults.byokConfigured else {
                preferences.getBoolean(KEY_BYOK_CONFIGURED, defaults.byokConfigured)
            },
            maxModelRetries = preferences.getInt(KEY_MAX_MODEL_RETRIES, defaults.maxModelRetries),
            maxModelRequestTimeoutSeconds = preferences.getInt(
                KEY_MAX_MODEL_REQUEST_TIMEOUT_SECONDS,
                defaults.maxModelRequestTimeoutSeconds
            ),
            providers = if (rawProviders.isNullOrBlank()) defaults.providers else decodedProviders,
            rawResponseCaptureEnabled = preferences.getBoolean(
                KEY_RAW_RESPONSE_CAPTURE_ENABLED,
                defaults.rawResponseCaptureEnabled
            )
        ).normalized()
    }

    private companion object {
        const val PREFERENCES_NAME = "agent_settings"
        const val KEY_PROVIDER_ID = "providerId"
        const val KEY_MODEL_ID = "modelId"
        const val KEY_GATEWAY_BASE_URL = "gatewayBaseUrl"
        const val KEY_PRIVACY_MODE = "privacyMode"
        const val KEY_CONSENT_VERSION = "firstUseConsentVersion"
        const val KEY_PREVIEW_ENABLED = "requestPreviewEnabled"
        const val KEY_BYOK_CONFIGURED = "byokConfigured"
        const val KEY_MAX_MODEL_RETRIES = "maxModelRetries"
        const val KEY_MAX_MODEL_REQUEST_TIMEOUT_SECONDS = "maxModelRequestTimeoutSeconds"
        const val KEY_PROVIDERS = "providers"
        const val KEY_RAW_RESPONSE_CAPTURE_ENABLED = "rawResponseCaptureEnabled"
        const val LOG_TAG = "LayAnalyzer-AgentSettings"
    }
}

/** Versioned, item-tolerant codec for non-secret provider configuration. */
internal object AgentProviderConfigCodec {
    private const val SCHEMA_VERSION = 2

    /**
     * The last version whose `prompt_only` was a default rather than a choice.
     *
     * Version 1 wrote every provider's response format explicitly, including the
     * `prompt_only` nobody picked — it was simply the default of the day. Reading
     * those back verbatim would keep the exact configuration that let a model
     * answer with prose wrapped around hand-written JSON, so version 1 records
     * are migrated to the current default. From version 2 on, a stored
     * `prompt_only` is a real choice and is preserved.
     */
    private const val LAST_IMPLICIT_PROMPT_ONLY_VERSION = 1

    fun encode(providers: List<AgentProviderConfig>): String = JSONObject()
        .put("version", SCHEMA_VERSION)
        .put("providers", JSONArray().apply {
            providers.forEach { provider ->
                put(JSONObject().apply {
                    put("id", provider.id)
                    put("name", provider.name)
                    put("baseUrl", provider.baseUrl)
                    put("apiType", provider.apiType.storageKey)
                    put("chatResponseFormat", provider.chatResponseFormat.storageKey)
                    put("apiKeyConfigured", provider.apiKeyConfigured)
                    provider.secretKeyAlias?.let { put("secretKeyAlias", it) }
                    put("models", JSONArray().apply {
                        provider.models.forEach { model ->
                            put(JSONObject().apply {
                                put("id", model.id)
                                put("name", model.name)
                                model.contextLimitTokens?.let { put("contextLimitTokens", it) }
                                model.outputLimitTokens?.let { put("outputLimitTokens", it) }
                                if (model.reasoningEffort.isConfigured) {
                                    put("reasoningEffort", model.reasoningEffort.storageKey)
                                }
                            })
                        }
                    })
                })
            }
        })
        .toString()

    fun decode(raw: String?, onWarning: (String) -> Unit = {}): List<AgentProviderConfig> {
        if (raw.isNullOrBlank()) return emptyList()
        var storedVersion = SCHEMA_VERSION
        val array = runCatching {
            when (val root = JSONTokener(raw).nextValue()) {
                is JSONArray -> root
                is JSONObject -> {
                    val version = root.optInt("version", -1)
                    require(version in 1..SCHEMA_VERSION) { "unsupported_schema_version" }
                    storedVersion = version
                    root.optJSONArray("providers")
                        ?: throw IllegalArgumentException("missing_providers_array")
                }
                else -> throw IllegalArgumentException("invalid_provider_envelope")
            }
        }.getOrElse { failure ->
            onWarning("Provider settings envelope was rejected: ${failure.message.orEmpty()}")
            return emptyList()
        }

        val promptOnlyWasImplicit = storedVersion <= LAST_IMPLICIT_PROMPT_ONLY_VERSION
        return buildList {
            for (index in 0 until array.length()) {
                val decoded = runCatching {
                    decodeProvider(
                        provider = array.optJSONObject(index)
                            ?: throw IllegalArgumentException("provider_is_not_an_object"),
                        upgradeImplicitPromptOnly = promptOnlyWasImplicit
                    )
                }.getOrElse { failure ->
                    onWarning(
                        "Provider settings entry $index was rejected: ${failure.message.orEmpty()}"
                    )
                    null
                }
                if (decoded != null) add(decoded)
            }
        }
    }

    private fun decodeProvider(
        provider: JSONObject,
        upgradeImplicitPromptOnly: Boolean = false
    ): AgentProviderConfig {
        val id = provider.string("id").trim()
        require(id.isNotBlank()) { "blank_provider_id" }
        val apiType = AgentApiType.fromStorage(provider.optionalString("apiType"))
            ?: throw IllegalArgumentException("unknown_api_type")
        val storedFormat = AgentChatResponseFormat.fromStorage(
            provider.optionalString("chatResponseFormat")
        ) ?: throw IllegalArgumentException("unknown_chat_response_format")
        val chatResponseFormat = if (
            upgradeImplicitPromptOnly && storedFormat == AgentChatResponseFormat.PROMPT_ONLY
        ) {
            AgentChatResponseFormat.JSON_OBJECT
        } else {
            storedFormat
        }
        val models = provider.opt("models").let { rawModels ->
            if (rawModels == null || rawModels == JSONObject.NULL) return@let emptyList()
            val array = rawModels as? JSONArray
                ?: throw IllegalArgumentException("models_is_not_an_array")
            buildList {
                for (index in 0 until array.length()) {
                    val model = array.optJSONObject(index)
                        ?: throw IllegalArgumentException("model_is_not_an_object")
                    val modelId = model.string("id").trim()
                    require(modelId.isNotBlank()) { "blank_model_id" }
                    add(
                        AgentModelConfig(
                            id = modelId,
                            name = model.optionalString("name"),
                            contextLimitTokens = model.optionalInt("contextLimitTokens"),
                            outputLimitTokens = model.optionalInt("outputLimitTokens"),
                            reasoningEffort = AgentReasoningEffort.fromStorage(
                                model.optionalString("reasoningEffort")
                            ) ?: throw IllegalArgumentException("unknown_reasoning_effort")
                        )
                    )
                }
            }
        }
        return AgentProviderConfig(
            id = id,
            name = provider.optionalString("name"),
            baseUrl = provider.optionalString("baseUrl"),
            models = models,
            apiKeyConfigured = provider.optBoolean("apiKeyConfigured", false),
            secretKeyAlias = provider.optionalString("secretKeyAlias").ifBlank { null },
            apiType = apiType,
            chatResponseFormat = chatResponseFormat
        ).normalized()
    }

    private fun JSONObject.string(name: String): String = opt(name) as? String
        ?: throw IllegalArgumentException("${name}_is_not_a_string")

    private fun JSONObject.optionalString(name: String): String = when (val value = opt(name)) {
        null, JSONObject.NULL -> ""
        is String -> value
        else -> throw IllegalArgumentException("${name}_is_not_a_string")
    }

    private fun JSONObject.optionalInt(name: String): Int? = when (val value = opt(name)) {
        null, JSONObject.NULL -> null
        is Number -> value.toLong().let { raw ->
            require(raw in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()) {
                "${name}_out_of_range"
            }
            raw.toInt()
        }
        else -> throw IllegalArgumentException("${name}_is_not_an_integer")
    }
}

/** Naming aliases for callers that prefer the platform-specific name. */
typealias AndroidAgentSettingsStore = SharedPreferencesAgentSettingsStore
typealias PersistentAgentSettingsStore = SharedPreferencesAgentSettingsStore
