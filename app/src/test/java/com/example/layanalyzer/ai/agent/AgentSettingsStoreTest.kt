package com.example.layanalyzer.ai.agent

import android.content.SharedPreferences
import com.example.layanalyzer.model.AgentPrivacyMode
import java.lang.reflect.Proxy
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentSettingsStoreTest {
    @Test
    fun legacyLocalOnlyPrivacyModeMigratesToRedactedMetadata() {
        assertEquals(
            AgentPrivacyMode.RedactedMetadata,
            storedPrivacyMode("LocalOnly", AgentPrivacyMode.RedactedMetadata)
        )
        assertEquals(
            AgentPrivacyMode.UnredactedMetadata,
            storedPrivacyMode("UnredactedMetadata", AgentPrivacyMode.RedactedMetadata)
        )
        assertEquals(
            AgentPrivacyMode.RedactedMetadata,
            storedPrivacyMode("SelectedPayload", AgentPrivacyMode.RedactedMetadata)
        )
        assertEquals(
            AgentPrivacyMode.RedactedMetadata,
            storedPrivacyMode("Unknown", AgentPrivacyMode.RedactedMetadata)
        )
    }

    @Test
    fun legacySingleProviderBecomesOneConfiguredProvider() {
        val normalized = AgentSettings(
            providerId = AgentSettings.LOCAL_PROVIDER_ID,
            modelId = "gpt-4o-mini",
            gatewayBaseUrl = " https://api.example/v1/ ",
            byokConfigured = true
        ).normalized()

        assertEquals(AgentSettings.OPENAI_COMPATIBLE_PROVIDER_ID, normalized.providerId)
        assertEquals("https://api.example/v1", normalized.gatewayBaseUrl)
        assertEquals(1, normalized.providers.size)
        assertEquals("gpt-4o-mini", normalized.providers.single().models.single().id)
        assertTrue(normalized.providers.single().apiKeyConfigured)
    }

    @Test
    fun selectedProviderProjectsItsEndpointAndKeyState() {
        val normalized = AgentSettings(
            providerId = "provider-b",
            modelId = "model-b-2",
            privacyMode = AgentPrivacyMode.RedactedMetadata,
            providers = listOf(
                AgentProviderConfig(
                    id = "provider-a",
                    name = "Provider A",
                    baseUrl = "https://a.example",
                    models = listOf(AgentModelConfig("model-a")),
                    apiKeyConfigured = false
                ),
                AgentProviderConfig(
                    id = "provider-b",
                    name = "Provider B",
                    baseUrl = " https://b.example/v1/ ",
                    models = listOf(
                        AgentModelConfig("model-b-1"),
                        AgentModelConfig("model-b-2", "Reasoning")
                    ),
                    apiKeyConfigured = true,
                    secretKeyAlias = "provider-b"
                )
            )
        ).normalized()

        assertEquals("Provider B", normalized.activeProvider?.name)
        assertEquals("https://b.example/v1", normalized.gatewayBaseUrl)
        assertEquals("Reasoning", normalized.activeModel?.name)
        assertTrue(normalized.byokConfigured)
    }

    @Test
    fun providerModelsAreTrimmedAndDeduplicated() {
        val provider = AgentProviderConfig(
            id = " p ",
            name = " ",
            models = listOf(
                AgentModelConfig(" model ", " "),
                AgentModelConfig("model", "Duplicate")
            )
        ).normalized()

        assertEquals("p", provider.id)
        assertEquals("p", provider.name)
        assertEquals(1, provider.models.size)
        assertEquals("model", provider.models.single().id)
        // A blank display name stays blank so the editor does not show a value
        // the user never typed; the id is resolved at render time instead.
        assertEquals("", provider.models.single().name)
        assertEquals("model", provider.models.single().displayName)
    }

    @Test
    fun blankModelNameFallsBackToIdOnlyForDisplay() {
        val explicit = AgentModelConfig("m", "Readable").normalized()
        assertEquals("Readable", explicit.name)
        assertEquals("Readable", explicit.displayName)

        val blank = AgentModelConfig("  us.anthropic.claude-sonnet-4  ", "   ").normalized()
        assertEquals("us.anthropic.claude-sonnet-4", blank.id)
        assertEquals("", blank.name)
        assertEquals("us.anthropic.claude-sonnet-4", blank.displayName)
    }

    @Test
    fun apiTypeAliasesAndLegacyValuesNormalizeToKnownProtocols() {
        assertEquals(AgentApiType.OPENAI_RESPONSES, AgentApiType.fromStorage("openai_response"))
        assertEquals(AgentApiType.OPENAI_RESPONSES, AgentApiType.OPENAI_RESPONSE)
        assertEquals(AgentApiType.ANTHROPIC_API, AgentApiType.fromStorage("anthropic_messages"))
        assertEquals(AgentApiType.OPENAI_CHAT_COMPLETIONS, AgentApiType.fromStorage(""))
        assertNull(AgentApiType.fromStorage("missing-or-legacy"))
    }

    @Test
    fun providerCodecWritesVersionedEnvelopeAndRoundTrips() {
        val provider = AgentProviderConfig(
            id = "provider-a",
            name = "Provider A",
            baseUrl = "https://a.example/v1",
            models = listOf(
                AgentModelConfig(
                    "model-a",
                    "Model A",
                    contextLimitTokens = 96_000,
                    outputLimitTokens = 328_000
                )
            ),
            apiKeyConfigured = true,
            secretKeyAlias = "provider-a-key",
            apiType = AgentApiType.OPENAI_CHAT_COMPLETIONS,
            chatResponseFormat = AgentChatResponseFormat.JSON_SCHEMA
        )

        val encoded = AgentProviderConfigCodec.encode(listOf(provider))
        val decoded = AgentProviderConfigCodec.decode(encoded)

        assertEquals(2, JSONObject(encoded).getInt("version"))
        assertEquals(listOf(provider), decoded)
    }

    /**
     * A provider saved before this setting existed must not stay on prompt-only:
     * that is the configuration under which a model answers with prose wrapped
     * around hand-written JSON, and one dropped delimiter then costs the run.
     */
    @Test
    fun legacyProviderDefaultsToJsonObjectResponseFormatting() {
        val legacy = JSONObject()
            .put("version", 1)
            .put(
                "providers",
                JSONArray().put(
                    JSONObject()
                        .put("id", "legacy")
                        .put("apiType", "openai_chat_completions")
                        .put("models", JSONArray().put(JSONObject().put("id", "model")))
                )
            )

        val provider = AgentProviderConfigCodec.decode(legacy.toString()).single()

        assertEquals(AgentChatResponseFormat.JSON_OBJECT, provider.chatResponseFormat)
    }

    /**
     * Version 1 wrote `prompt_only` for every provider because it was that
     * version's default, not a user's choice, so those records are migrated
     * rather than trusted.
     */
    @Test
    fun schemaVersionOneProvidersAreMigratedOffImplicitPromptOnly() {
        val legacy = JSONObject()
            .put("version", 1)
            .put(
                "providers",
                JSONArray().put(
                    JSONObject()
                        .put("id", "legacy")
                        .put("apiType", "openai_chat_completions")
                        .put("chatResponseFormat", "prompt_only")
                        .put("models", JSONArray().put(JSONObject().put("id", "model")))
                )
            )

        val provider = AgentProviderConfigCodec.decode(legacy.toString()).single()

        assertEquals(AgentChatResponseFormat.JSON_OBJECT, provider.chatResponseFormat)
    }

    /** From version 2 on, a stored prompt-only is a deliberate choice. */
    @Test
    fun explicitPromptOnlyResponseFormattingIsPreserved() {
        val stored = JSONObject()
            .put("version", 2)
            .put(
                "providers",
                JSONArray().put(
                    JSONObject()
                        .put("id", "explicit")
                        .put("apiType", "openai_chat_completions")
                        .put("chatResponseFormat", "prompt_only")
                        .put("models", JSONArray().put(JSONObject().put("id", "model")))
                )
            )

        val provider = AgentProviderConfigCodec.decode(stored.toString()).single()

        assertEquals(AgentChatResponseFormat.PROMPT_ONLY, provider.chatResponseFormat)
    }

    @Test
    fun rawResponseCaptureSettingPersistsAcrossStoreInstances() {
        val preferences = memoryPreferences()
        val first = SharedPreferencesAgentSettingsStore(preferences)

        assertFalse(first.settings.rawResponseCaptureEnabled)
        first.update(first.settings.copy(rawResponseCaptureEnabled = true))

        val restored = SharedPreferencesAgentSettingsStore(preferences)
        assertTrue(restored.settings.rawResponseCaptureEnabled)
    }

    @Test
    fun modelRequestTimeoutPersistsAndIsClampedToTheSupportedRange() {
        val preferences = memoryPreferences()
        val store = SharedPreferencesAgentSettingsStore(preferences)

        assertEquals(
            (AgentPolicy.DEFAULT_MAX_MODEL_REQUEST_TIMEOUT_MILLIS / 1000L).toInt(),
            store.settings.maxModelRequestTimeoutSeconds
        )
        store.update(
            store.settings.copy(maxModelRequestTimeoutSeconds = 540)
        )
        val restored = SharedPreferencesAgentSettingsStore(preferences)
        assertEquals(540, restored.settings.maxModelRequestTimeoutSeconds)

        // Out-of-range values collapse to the boundary instead of crashing.
        store.update(restored.settings.copy(maxModelRequestTimeoutSeconds = 10_000))
        assertEquals(
            (AgentPolicy.MAX_MODEL_REQUEST_TIMEOUT_MILLIS / 1000L).toInt(),
            store.settings.maxModelRequestTimeoutSeconds
        )
        store.update(
            store.settings.copy(maxModelRequestTimeoutSeconds = 1)
        )
        assertEquals(
            AgentSettings.MIN_MODEL_REQUEST_TIMEOUT_SECONDS,
            store.settings.maxModelRequestTimeoutSeconds
        )
    }

    @Test
    fun reasoningEffortRoundTripsAndDefaultsWhenAbsent() {
        val provider = AgentProviderConfig(
            id = "provider-a",
            name = "Provider A",
            baseUrl = "https://a.example/v1",
            models = listOf(
                AgentModelConfig(
                    id = "reasoner",
                    name = "Reasoner",
                    reasoningEffort = AgentReasoningEffort.XHIGH
                )
            ),
            apiType = AgentApiType.OPENAI_CHAT_COMPLETIONS
        )

        val decoded = AgentProviderConfigCodec.decode(
            AgentProviderConfigCodec.encode(listOf(provider))
        ).single()

        assertEquals(AgentReasoningEffort.XHIGH, decoded.models.single().reasoningEffort)
        assertEquals("xhigh", AgentReasoningEffort.fromStorage("extra_high")?.storageKey)
        assertEquals(AgentReasoningEffort.UNSPECIFIED, AgentReasoningEffort.fromStorage(""))
        assertNull(AgentReasoningEffort.fromStorage("unknown-effort"))
    }

    @Test
    fun unknownReasoningEffortRejectsOnlyThatProvider() {
        val encoded = JSONObject()
            .put("version", 2)
            .put(
                "providers",
                JSONArray()
                    .put(
                        JSONObject()
                            .put("id", "bad")
                            .put("apiType", "openai_chat_completions")
                            .put(
                                "models",
                                JSONArray().put(
                                    JSONObject()
                                        .put("id", "model")
                                        .put("reasoningEffort", "future_effort")
                                )
                            )
                    )
                    .put(
                        JSONObject()
                            .put("id", "good")
                            .put("apiType", "openai_chat_completions")
                            .put("models", JSONArray().put(JSONObject().put("id", "model")))
                    )
            )
            .toString()
        val warnings = mutableListOf<String>()

        val decoded = AgentProviderConfigCodec.decode(encoded, warnings::add)

        assertEquals(listOf("good"), decoded.map { it.id })
        assertEquals(AgentReasoningEffort.UNSPECIFIED, decoded.single().models.single().reasoningEffort)
        assertTrue(warnings.single().contains("unknown_reasoning_effort"))
    }

    @Test
    fun legacyProviderModelWithoutLimitsStillDecodes() {
        val legacy = JSONObject()
            .put("version", 1)
            .put(
                "providers",
                JSONArray().put(
                    JSONObject()
                        .put("id", "legacy")
                        .put("models", JSONArray().put(JSONObject().put("id", "model")))
                )
            )

        val model = AgentProviderConfigCodec.decode(legacy.toString()).single().models.single()

        assertNull(model.contextLimitTokens)
        assertNull(model.outputLimitTokens)
        assertEquals(AgentReasoningEffort.UNSPECIFIED, model.reasoningEffort)
    }

    @Test
    fun invalidConfiguredModelLimitsAreRejectedByProviderCodec() {
        val invalid = JSONObject()
            .put("version", 1)
            .put(
                "providers",
                JSONArray().put(
                    JSONObject()
                        .put("id", "invalid")
                        .put(
                            "models",
                            JSONArray().put(
                                JSONObject()
                                    .put("id", "model")
                                    .put("outputLimitTokens", 1)
                            )
                        )
                )
            )
        val warnings = mutableListOf<String>()

        assertTrue(AgentProviderConfigCodec.decode(invalid.toString(), warnings::add).isEmpty())
        assertTrue(warnings.single().contains("outputLimitTokens"))
    }

    @Test
    fun malformedProviderDoesNotHideOtherEntries() {
        val valid = JSONObject()
            .put("id", "valid")
            .put("name", "Valid")
            .put("baseUrl", "https://valid.example")
            .put("apiType", "anthropic_api")
            .put("models", JSONArray().put(JSONObject().put("id", "claude")))
        val encoded = JSONObject()
            .put("version", 1)
            .put("providers", JSONArray().put("broken").put(valid))
            .toString()
        val warnings = mutableListOf<String>()

        val decoded = AgentProviderConfigCodec.decode(encoded, warnings::add)

        assertEquals(listOf("valid"), decoded.map { it.id })
        assertEquals(AgentApiType.ANTHROPIC_API, decoded.single().apiType)
        assertEquals(1, warnings.size)
    }

    @Test
    fun legacyBareArrayStillLoads() {
        val legacy = JSONArray().put(
            JSONObject()
                .put("id", "legacy")
                .put("name", "Legacy")
                .put("baseUrl", "https://legacy.example")
                .put("models", JSONArray().put(JSONObject().put("id", "legacy-model")))
        )

        val decoded = AgentProviderConfigCodec.decode(legacy.toString())

        assertEquals("legacy", decoded.single().id)
        assertEquals(AgentApiType.OPENAI_CHAT_COMPLETIONS, decoded.single().apiType)
    }

    @Test
    fun unknownApiTypeRejectsOnlyThatProviderAndEmitsWarning() {
        fun provider(id: String, apiType: String) = JSONObject()
            .put("id", id)
            .put("apiType", apiType)
            .put("models", JSONArray().put(JSONObject().put("id", "model")))
        val encoded = JSONObject()
            .put("version", 1)
            .put(
                "providers",
                JSONArray()
                    .put(provider("unknown", "future_protocol"))
                    .put(provider("known", "openai_chat_completions"))
            )
            .toString()
        val warnings = mutableListOf<String>()

        val decoded = AgentProviderConfigCodec.decode(encoded, warnings::add)

        assertEquals(listOf("known"), decoded.map { it.id })
        assertTrue(warnings.single().contains("unknown_api_type"))
    }

    private fun memoryPreferences(): SharedPreferences {
        val values = linkedMapOf<String, Any?>()
        lateinit var editor: SharedPreferences.Editor
        editor = Proxy.newProxyInstance(
            SharedPreferences.Editor::class.java.classLoader,
            arrayOf(SharedPreferences.Editor::class.java)
        ) { _, method, args ->
            val arguments = args.orEmpty()
            when (method.name) {
                "putString", "putStringSet", "putInt", "putLong", "putFloat", "putBoolean" -> {
                    val key = arguments[0] as String
                    val value = arguments.getOrNull(1)
                    if (value == null) values.remove(key) else values[key] = value
                    editor
                }
                "remove" -> {
                    values.remove(arguments[0] as String)
                    editor
                }
                "clear" -> {
                    values.clear()
                    editor
                }
                "commit" -> true
                "apply" -> null
                else -> editor
            }
        } as SharedPreferences.Editor

        return Proxy.newProxyInstance(
            SharedPreferences::class.java.classLoader,
            arrayOf(SharedPreferences::class.java)
        ) { _, method, args ->
            val arguments = args.orEmpty()
            val key = arguments.getOrNull(0) as? String
            when (method.name) {
                "getAll" -> values.toMap()
                "getString" -> values[key] as? String ?: arguments.getOrNull(1)
                "getStringSet" -> values[key] as? Set<*> ?: arguments.getOrNull(1)
                "getInt" -> values[key] as? Int ?: arguments[1]
                "getLong" -> values[key] as? Long ?: arguments[1]
                "getFloat" -> values[key] as? Float ?: arguments[1]
                "getBoolean" -> values[key] as? Boolean ?: arguments[1]
                "contains" -> values.containsKey(key)
                "edit" -> editor
                "registerOnSharedPreferenceChangeListener",
                "unregisterOnSharedPreferenceChangeListener" -> null
                else -> null
            }
        } as SharedPreferences
    }
}
