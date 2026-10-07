// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.layanalyzer.R
import com.example.layanalyzer.ai.agent.AgentApiType
import com.example.layanalyzer.ai.agent.AgentChatResponseFormat
import com.example.layanalyzer.ai.agent.AgentModelConfig
import com.example.layanalyzer.ai.agent.AgentReasoningEffort
import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.ai.agent.AgentProviderConfig
import com.example.layanalyzer.ai.agent.AgentSettings
import com.example.layanalyzer.ai.client.MockModelScriptLibrary
import com.example.layanalyzer.ai.client.ProviderModelFetchFailure
import com.example.layanalyzer.ai.client.ProviderModelFetchResult
import kotlinx.coroutines.launch

/** Global AI configuration: providers own endpoints and may expose many models. */
@Composable
fun AgentModelSettingsDialog(
    settings: AgentSettings,
    byokEnabled: Boolean,
    onSettingsChange: (AgentSettings) -> Unit,
    onSaveProviderKey: (AgentProviderConfig, String) -> Unit,
    onClearProviderKey: (String) -> Unit,
    onDismiss: () -> Unit,
    debugResponseCaptureAvailable: Boolean = false,
    onClearResponseDumps: () -> Unit = {},
    onFetchProviderModels: suspend (AgentProviderConfig, String) -> ProviderModelFetchResult =
        { _, _ -> ProviderModelFetchResult.Failure(ProviderModelFetchFailure.Network) }
) {
    val normalizedSettings = settings.normalized()
    var providers by remember(settings.providers) {
        mutableStateOf(normalizedSettings.providers)
    }
    var previewEnabled by remember(settings.requestPreviewEnabled) {
        mutableStateOf(settings.requestPreviewEnabled)
    }
    var maxRetriesText by remember(settings.maxModelRetries) {
        mutableStateOf(settings.maxModelRetries.toString())
    }
    var maxTimeoutText by remember(settings.maxModelRequestTimeoutSeconds) {
        mutableStateOf(settings.maxModelRequestTimeoutSeconds.toString())
    }
    var rawResponseCaptureEnabled by remember(settings.rawResponseCaptureEnabled) {
        mutableStateOf(settings.rawResponseCaptureEnabled)
    }
    var editingProvider by remember { mutableStateOf<AgentProviderConfig?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.agent_model_settings_title)) },
        text = {
            // One scroller for providers and analysis options. A nested
            // LazyColumn with a large max height used to consume the dialog
            // slot and clip the retry field plus the dump-clear button.
            Column(
                modifier = Modifier
                    .widthIn(max = 640.dp)
                    .heightIn(max = 520.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = stringResource(R.string.agent_model_settings_description),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                providers.forEach { provider ->
                    key(provider.id) {
                        AgentProviderRow(
                            provider = provider,
                            selected = provider.id == normalizedSettings.providerId,
                            byokEnabled = byokEnabled,
                            onEdit = { editingProvider = provider },
                            onDelete = {
                                providers = providers.filterNot { it.id == provider.id }
                            }
                        )
                    }
                }
                TextButton(
                    onClick = {
                        val id = "provider-${System.currentTimeMillis()}"
                        editingProvider = AgentProviderConfig(
                            id = id,
                            name = "",
                            models = listOf(AgentModelConfig(id = "", name = "")),
                            secretKeyAlias = id
                        )
                    }
                ) {
                    Icon(Icons.Default.Add, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.agent_add_provider))
                }
                HorizontalDivider(Modifier.padding(vertical = 6.dp))
                Text(
                    text = stringResource(R.string.agent_analysis_options),
                    style = MaterialTheme.typography.titleSmall
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = stringResource(R.string.agent_preview_enabled),
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodySmall
                    )
                    Switch(checked = previewEnabled, onCheckedChange = { previewEnabled = it })
                }
                OutlinedTextField(
                    value = maxRetriesText,
                    onValueChange = { maxRetriesText = it.filter(Char::isDigit).take(2) },
                    label = { Text(stringResource(R.string.agent_model_retry_count)) },
                    supportingText = {
                        Text(
                            stringResource(
                                R.string.agent_model_retry_count_supporting,
                                AgentPolicy.MAX_MODEL_RETRIES
                            )
                        )
                    },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = maxTimeoutText,
                    onValueChange = { maxTimeoutText = it.filter(Char::isDigit).take(4) },
                    label = { Text(stringResource(R.string.agent_model_request_timeout)) },
                    supportingText = {
                        Text(
                            stringResource(
                                R.string.agent_model_request_timeout_supporting,
                                AgentSettings.MIN_MODEL_REQUEST_TIMEOUT_SECONDS,
                                (AgentPolicy.MAX_MODEL_REQUEST_TIMEOUT_MILLIS / 1000L).toInt()
                            )
                        )
                    },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                if (debugResponseCaptureAvailable) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = stringResource(R.string.agent_response_dumps_enabled),
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.bodySmall
                        )
                        Switch(
                            checked = rawResponseCaptureEnabled,
                            onCheckedChange = { rawResponseCaptureEnabled = it }
                        )
                    }
                    Text(
                        text = stringResource(R.string.agent_response_dumps_warning),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                    TextButton(onClick = onClearResponseDumps) {
                        Text(stringResource(R.string.agent_response_dumps_clear))
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    // Deleting every provider (including the local mock entry)
                    // must not strand the active selection on a removed id.
                    // Re-point the active provider/model at the first remaining
                    // provider with models, or reset to the built-in offline
                    // demo when nothing remains.
                    val activeStillConfigured = providers.any { provider ->
                        provider.id == normalizedSettings.providerId &&
                            provider.models.any { it.id == normalizedSettings.modelId }
                    }
                    val fallbackProvider = providers.firstOrNull { it.models.isNotEmpty() }
                        ?: providers.firstOrNull()
                    val nextProviderId = when {
                        activeStillConfigured -> normalizedSettings.providerId
                        fallbackProvider != null -> fallbackProvider.id
                        else -> AgentSettings.LOCAL_PROVIDER_ID
                    }
                    val nextModelId = when {
                        activeStillConfigured -> normalizedSettings.modelId
                        fallbackProvider?.models?.firstOrNull() != null ->
                            fallbackProvider.models.first().id
                        else -> MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS
                    }
                    onSettingsChange(
                        settings.copy(
                            providers = providers,
                            providerId = nextProviderId,
                            modelId = nextModelId,
                            // Falling back to the built-in offline demo must
                            // also drop the endpoint fields: a stale gateway
                            // URL plus the local provider id is exactly the
                            // legacy shape normalized() migrates back into a
                            // cloud provider, which would resurrect the entry
                            // the user just deleted. A remaining active
                            // provider gets its endpoint projected by
                            // normalized() anyway.
                            gatewayBaseUrl = if (!activeStillConfigured &&
                                nextProviderId == AgentSettings.LOCAL_PROVIDER_ID
                            ) {
                                ""
                            } else {
                                settings.gatewayBaseUrl
                            },
                            byokConfigured = if (!activeStillConfigured &&
                                nextProviderId == AgentSettings.LOCAL_PROVIDER_ID
                            ) {
                                false
                            } else {
                                settings.byokConfigured
                            },
                            requestPreviewEnabled = previewEnabled,
                            rawResponseCaptureEnabled = rawResponseCaptureEnabled,
                            maxModelRetries = maxRetriesText.toIntOrNull()
                                ?.coerceIn(0, AgentPolicy.MAX_MODEL_RETRIES)
                                ?: settings.maxModelRetries,
                            maxModelRequestTimeoutSeconds = maxTimeoutText.toIntOrNull()
                                ?.coerceIn(
                                    AgentSettings.MIN_MODEL_REQUEST_TIMEOUT_SECONDS,
                                    (AgentPolicy.MAX_MODEL_REQUEST_TIMEOUT_MILLIS / 1000L).toInt()
                                )
                                ?: settings.maxModelRequestTimeoutSeconds
                        )
                    )
                    onDismiss()
                }
            ) {
                Text(stringResource(R.string.save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )

    val currentEditingProvider = editingProvider?.let { draft ->
        providers.firstOrNull { it.id == draft.id } ?: draft
    }
    currentEditingProvider?.let { provider ->
        AgentProviderEditorDialog(
            provider = provider,
            byokEnabled = byokEnabled,
            onDismiss = { editingProvider = null },
            onSave = { updated ->
                providers = providers.filterNot { it.id == updated.id } + updated
                editingProvider = null
            },
            onFetchModels = onFetchProviderModels,
            onSaveProviderKey = { draft, secret ->
                onSaveProviderKey(draft, secret)
                val saved = draft.copy(apiKeyConfigured = true)
                providers = if (providers.any { it.id == saved.id }) {
                    providers.map { if (it.id == saved.id) saved else it }
                } else {
                    providers + saved
                }
            },
            onClearProviderKey = { providerId ->
                onClearProviderKey(providerId)
                providers = providers.map {
                    if (it.id == providerId) it.copy(apiKeyConfigured = false) else it
                }
            }
        )
    }
}

@Composable
private fun AgentProviderRow(
    provider: AgentProviderConfig,
    selected: Boolean,
    byokEnabled: Boolean,
    onEdit: () -> Unit,
    onDelete: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(Modifier.padding(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(provider.name, style = MaterialTheme.typography.titleSmall)
                        if (selected) {
                            Spacer(Modifier.width(8.dp))
                            Text(
                                stringResource(R.string.agent_current_model),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                    Text(
                        text = provider.baseUrl.ifBlank {
                            stringResource(R.string.agent_local_provider)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    if (provider.id != AgentSettings.LOCAL_PROVIDER_ID) {
                        Text(
                            text = apiTypeLabel(provider.apiType),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
                IconButton(onClick = onEdit) {
                    Icon(
                        Icons.Default.Edit,
                        contentDescription = stringResource(R.string.agent_edit_provider)
                    )
                }
                // Every provider is deletable, including the built-in local
                // mock provider: removing it simply stops advertising the
                // offline demo, and the model card falls back to whatever
                // remains (or the default mock entry recreated on save).
                IconButton(onClick = onDelete) {
                    Icon(
                        Icons.Default.Delete,
                        contentDescription = stringResource(R.string.agent_delete_provider)
                    )
                }
            }
            Text(
                text = if (provider.models.isEmpty()) {
                    stringResource(R.string.agent_no_models)
                } else {
                    stringResource(
                        R.string.agent_provider_models,
                        // displayName, not name: a model added without an
                        // explicit label must still read as its id here.
                        provider.models.joinToString { it.displayName }
                    )
                },
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            if (byokEnabled && provider.id != AgentSettings.LOCAL_PROVIDER_ID) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Key, contentDescription = null, Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(
                        text = if (provider.apiKeyConfigured) {
                            stringResource(R.string.agent_byok_configured)
                        } else {
                            stringResource(R.string.agent_byok_not_configured)
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Composable
private fun apiTypeLabel(apiType: AgentApiType): String = stringResource(
    when (apiType) {
        AgentApiType.OPENAI_CHAT_COMPLETIONS -> R.string.agent_api_type_openai_chat
        AgentApiType.OPENAI_RESPONSES -> R.string.agent_api_type_openai_responses
        AgentApiType.ANTHROPIC_API -> R.string.agent_api_type_anthropic
    }
)

@Composable
private fun chatResponseFormatLabel(format: AgentChatResponseFormat): String = stringResource(
    when (format) {
        AgentChatResponseFormat.PROMPT_ONLY -> R.string.agent_chat_response_format_prompt
        AgentChatResponseFormat.JSON_OBJECT -> R.string.agent_chat_response_format_json_object
        AgentChatResponseFormat.JSON_SCHEMA -> R.string.agent_chat_response_format_json_schema
    }
)

@Composable
private fun reasoningEffortLabel(effort: AgentReasoningEffort): String = stringResource(
    when (effort) {
        AgentReasoningEffort.UNSPECIFIED -> R.string.agent_reasoning_effort_default
        AgentReasoningEffort.NONE -> R.string.agent_reasoning_effort_none
        AgentReasoningEffort.MINIMAL -> R.string.agent_reasoning_effort_minimal
        AgentReasoningEffort.LOW -> R.string.agent_reasoning_effort_low
        AgentReasoningEffort.MEDIUM -> R.string.agent_reasoning_effort_medium
        AgentReasoningEffort.HIGH -> R.string.agent_reasoning_effort_high
        AgentReasoningEffort.XHIGH -> R.string.agent_reasoning_effort_xhigh
    }
)

@Composable
private fun fetchModelsFailureMessage(failure: ProviderModelFetchFailure): String =
    stringResource(
        when (failure) {
            ProviderModelFetchFailure.MissingBaseUrl -> R.string.agent_fetch_models_missing_base_url
            ProviderModelFetchFailure.MissingApiKey -> R.string.agent_fetch_models_missing_key
            ProviderModelFetchFailure.InsecureEndpoint -> R.string.agent_fetch_models_https_required
            ProviderModelFetchFailure.Network -> R.string.agent_fetch_models_network
            ProviderModelFetchFailure.Timeout -> R.string.agent_fetch_models_timeout
            ProviderModelFetchFailure.Authentication -> R.string.agent_fetch_models_auth
            ProviderModelFetchFailure.Server -> R.string.agent_fetch_models_server
            ProviderModelFetchFailure.MalformedResponse -> R.string.agent_fetch_models_malformed
            ProviderModelFetchFailure.Empty -> R.string.agent_fetch_models_empty
        }
    )

/** Model id input; always visible, even while the advanced region is collapsed. */
private const val MODEL_FIELD_ID = 0

/** Optional display name input; an empty value renders as the model id. */
private const val MODEL_FIELD_NAME = 1

/** Context-limit input, inside the advanced region. */
private const val MODEL_FIELD_CONTEXT_LIMIT = 2

/** Output-limit input, inside the advanced region. */
private const val MODEL_FIELD_OUTPUT_LIMIT = 3

/**
 * Width of the trailing column on a model row, taken by the advanced-region
 * chevron next to the model id input. The display name reserves the same space
 * so its right edge matches the id input, and the delete button on the
 * token-limit row sits in this column too, so it lines up with the chevron
 * rather than stopping short of it.
 */
private val MODEL_TOGGLE_WIDTH = 40.dp

/**
 * The text a model field should echo back. The two limit inputs render their
 * current raw text; the name input resolves to the model id when left blank so
 * the row never previews an empty string the user cannot act on.
 */
private fun AgentModelConfig.fieldText(field: Int): String = when (field) {
    MODEL_FIELD_ID -> id
    MODEL_FIELD_NAME -> displayName
    MODEL_FIELD_CONTEXT_LIMIT -> contextLimitTokens?.toString().orEmpty()
    else -> outputLimitTokens?.toString().orEmpty()
}

/**
 * The value an editor should open on. Unlike [fieldText] this never substitutes
 * the id for a blank name, so clearing and saving the name really clears it.
 */
private fun AgentModelConfig.editableText(field: Int): String = when (field) {
    MODEL_FIELD_NAME -> name
    else -> fieldText(field)
}

@Composable
private fun AgentProviderEditorDialog(
    provider: AgentProviderConfig,
    byokEnabled: Boolean,
    onDismiss: () -> Unit,
    onSave: (AgentProviderConfig) -> Unit,
    onFetchModels: suspend (AgentProviderConfig, String) -> ProviderModelFetchResult,
    onSaveProviderKey: (AgentProviderConfig, String) -> Unit,
    onClearProviderKey: (String) -> Unit
) {
    // Keyed on the id only: a settings emission mid-edit (e.g. after saving an
    // API key) must not clobber text the user is still typing.
    var name by remember(provider.id) { mutableStateOf(provider.name) }
    var baseUrl by remember(provider.id) { mutableStateOf(provider.baseUrl) }
    var models by remember(provider.id) {
        mutableStateOf(
            provider.models.ifEmpty { listOf(AgentModelConfig(id = "", name = "")) }
        )
    }
    var apiType by remember(provider.id) { mutableStateOf(provider.apiType) }
    var apiTypeMenuExpanded by remember { mutableStateOf(false) }
    var chatResponseFormat by remember(provider.id) {
        mutableStateOf(provider.chatResponseFormat)
    }
    var chatResponseFormatMenuExpanded by remember { mutableStateOf(false) }
    var reasoningEffortMenuIndex by remember { mutableStateOf<Int?>(null) }
    var apiKey by remember { mutableStateOf("") }
    val fetchScope = rememberCoroutineScope()
    var fetchingModels by remember(provider.id) { mutableStateOf(false) }
    var fetchFailure by remember(provider.id) { mutableStateOf<ProviderModelFetchFailure?>(null) }
    var fetchedModelIds by remember(provider.id) { mutableStateOf<List<String>>(emptyList()) }
    val fetchedSelection = remember(provider.id) { mutableStateMapOf<String, Boolean>() }
    val canFetchModels = baseUrl.isNotBlank() &&
        (apiKey.isNotBlank() || provider.apiKeyConfigured)
    val limitsValid = models.all { model ->
        (model.contextLimitTokens == null ||
            model.contextLimitTokens in AgentModelConfig.MIN_CONTEXT_LIMIT_TOKENS..AgentModelConfig.MAX_CONTEXT_LIMIT_TOKENS) &&
            (model.outputLimitTokens == null ||
                model.outputLimitTokens in AgentModelConfig.MIN_OUTPUT_LIMIT_TOKENS..AgentModelConfig.MAX_OUTPUT_LIMIT_TOKENS)
    }
    val canSave = name.isNotBlank() &&
        (provider.id == AgentSettings.LOCAL_PROVIDER_ID || baseUrl.isNotBlank()) &&
        models.any { it.id.isNotBlank() } &&
        limitsValid

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                if (provider.name.isBlank()) {
                    stringResource(R.string.agent_add_provider)
                } else {
                    stringResource(R.string.agent_edit_provider)
                }
            )
        },
        text = {
            LazyColumn(
                modifier = Modifier
                    .widthIn(max = 560.dp)
                    .heightIn(max = 520.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                item {
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it },
                        label = { Text(stringResource(R.string.agent_provider_name)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    // Same collision as in the model rows: the gateway URL label
                    // floats above its top border when focused.
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = baseUrl,
                        onValueChange = { baseUrl = it },
                        label = { Text(stringResource(R.string.agent_gateway_url)) },
                        supportingText = {
                            Text(stringResource(R.string.agent_gateway_https_only))
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Box {
                        TextButton(onClick = { apiTypeMenuExpanded = true }) {
                            Text(
                                stringResource(
                                    R.string.agent_api_type_value,
                                    apiTypeLabel(apiType)
                                )
                            )
                        }
                        DropdownMenu(
                            expanded = apiTypeMenuExpanded,
                            onDismissRequest = { apiTypeMenuExpanded = false }
                        ) {
                            AgentApiType.values().forEach { option ->
                                DropdownMenuItem(
                                    text = { Text(apiTypeLabel(option)) },
                                    onClick = {
                                        apiType = option
                                        apiTypeMenuExpanded = false
                                    }
                                )
                            }
                        }
                    }
                    if (apiType == AgentApiType.OPENAI_CHAT_COMPLETIONS) {
                        Box {
                            TextButton(onClick = { chatResponseFormatMenuExpanded = true }) {
                                Text(
                                    stringResource(
                                        R.string.agent_chat_response_format_value,
                                        chatResponseFormatLabel(chatResponseFormat)
                                    )
                                )
                            }
                            DropdownMenu(
                                expanded = chatResponseFormatMenuExpanded,
                                onDismissRequest = { chatResponseFormatMenuExpanded = false }
                            ) {
                                AgentChatResponseFormat.values().forEach { option ->
                                    DropdownMenuItem(
                                        text = { Text(chatResponseFormatLabel(option)) },
                                        onClick = {
                                            chatResponseFormat = option
                                            chatResponseFormatMenuExpanded = false
                                        }
                                    )
                                }
                            }
                        }
                        Text(
                            text = stringResource(R.string.agent_chat_response_format_supporting),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(
                        stringResource(R.string.agent_provider_models_title),
                        style = MaterialTheme.typography.titleSmall
                    )
                    if (provider.id != AgentSettings.LOCAL_PROVIDER_ID) {
                        Text(
                            text = stringResource(R.string.agent_reasoning_effort_supporting),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            TextButton(
                                onClick = {
                                    fetchingModels = true
                                    fetchFailure = null
                                    fetchScope.launch {
                                        val result = onFetchModels(
                                            editedProviderDraft(
                                                provider,
                                                name,
                                                baseUrl,
                                                models,
                                                apiType,
                                                chatResponseFormat
                                            ),
                                            apiKey
                                        )
                                        when (result) {
                                            is ProviderModelFetchResult.Success -> {
                                                fetchedModelIds = result.modelIds.filterNot { id ->
                                                    models.any { it.id == id }
                                                }
                                                fetchedSelection.clear()
                                            }
                                            is ProviderModelFetchResult.Failure -> {
                                                fetchedModelIds = emptyList()
                                                fetchedSelection.clear()
                                                fetchFailure = result.reason
                                            }
                                        }
                                        fetchingModels = false
                                    }
                                },
                                enabled = canFetchModels && !fetchingModels
                            ) {
                                Icon(Icons.Default.Refresh, contentDescription = null)
                                Spacer(Modifier.width(6.dp))
                                Text(stringResource(R.string.agent_fetch_models))
                            }
                        }
                        val fetchError = fetchFailure?.let { fetchModelsFailureMessage(it) }
                        when {
                            fetchingModels -> Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(16.dp),
                                    strokeWidth = 2.dp
                                )
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    stringResource(R.string.agent_fetch_models_fetching),
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                            fetchError != null -> Text(
                                text = fetchError,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                            fetchedModelIds.isNotEmpty() -> Text(
                                text = stringResource(R.string.agent_fetch_models_hint),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
                items(models.indices.toList(), key = { index -> "model-$index" }) { index ->
                    val model = models[index]
                    // Unkeyed on purpose: keying on model.id would reset all
                    // three values on every keystroke in the id field, since
                    // editing the id changes the key. The list item key already
                    // pins each row's composition slot.
                    //
                    // focusedField records which of the four inputs last held
                    // focus and is deliberately never cleared on blur, so the
                    // focus echo under the model id does not vanish on the way
                    // out.
                    var focusedField by remember { mutableStateOf<Int?>(null) }
                    var expandedField by remember { mutableStateOf<Int?>(null) }
                    // The display name, the token limits and the reasoning-effort
                    // menu live in this region, which starts collapsed: a model
                    // row shows only its id input until the chevron is tapped.
                    var regionExpanded by remember { mutableStateOf(false) }
                    val focusManager = LocalFocusManager.current
                    // Records the field for the focus echo. It deliberately does
                    // not open the advanced region — the chevron is the only
                    // control for that — so tapping the model id to edit it never
                    // springs the region open under the user's finger.
                    fun focusTarget(field: Int) {
                        focusedField = field
                    }
                    Column {
                        // The model id keeps the full remaining width; the
                        // advanced-region toggle lives on the same row as a bare
                        // chevron so it costs no extra height and only ~40dp of
                        // width. Right arrow = collapsed, down arrow = expanded.
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            OutlinedTextField(
                                value = model.id,
                                onValueChange = { value ->
                                    models = models.mapIndexed { modelIndex, current ->
                                        if (modelIndex == index) current.copy(id = value) else current
                                    }
                                },
                                label = { Text(stringResource(R.string.agent_model_id)) },
                                singleLine = true,
                                modifier = Modifier.weight(1f).onFocusChanged {
                                    if (it.isFocused) focusTarget(MODEL_FIELD_ID)
                                }
                            )
                            IconButton(
                                onClick = { regionExpanded = !regionExpanded },
                                modifier = Modifier.size(MODEL_TOGGLE_WIDTH)
                            ) {
                                Icon(
                                    imageVector = if (regionExpanded) {
                                        Icons.Default.KeyboardArrowDown
                                    } else {
                                        Icons.Default.KeyboardArrowRight
                                    },
                                    contentDescription = stringResource(
                                        if (regionExpanded) {
                                            R.string.agent_model_collapse_region
                                        } else {
                                            R.string.agent_model_expand_region
                                        }
                                    ),
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                        }
                        focusedField?.let { field ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = model.fieldText(field),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis,
                                    modifier = Modifier.weight(1f)
                                )
                                TextButton(onClick = { expandedField = field }) {
                                    Text(stringResource(R.string.agent_model_expand_editor))
                                }
                            }
                        }
                        expandedField?.let { field ->
                            ExpandedModelFieldDialog(
                                label = stringResource(
                                    if (field == MODEL_FIELD_ID) {
                                        R.string.agent_model_id
                                    } else {
                                        R.string.agent_model_name
                                    }
                                ),
                                // The raw stored value, not fieldText(): editing
                                // the name of a model that has none must start
                                // from empty, not from a prefilled model id the
                                // user never typed.
                                value = model.editableText(field),
                                onDismiss = { expandedField = null },
                                onSave = { value ->
                                    models = models.mapIndexed { modelIndex, current ->
                                        if (modelIndex != index) current
                                        else if (field == MODEL_FIELD_ID) current.copy(id = value)
                                        else current.copy(name = value)
                                    }
                                    expandedField = null
                                }
                            )
                        }
                        if (regionExpanded) {
                            // The focused label of each field floats above its
                            // top border; without a gap it collides with the
                            // field above (the model id field for the first one).
                            Spacer(Modifier.height(8.dp))
                            OutlinedTextField(
                                value = model.name,
                                onValueChange = { value ->
                                    models = models.mapIndexed { modelIndex, current ->
                                        if (modelIndex == index) current.copy(name = value) else current
                                    }
                                },
                                label = { Text(stringResource(R.string.agent_model_name)) },
                                // Optional: an empty name means "reuse the model
                                // id" everywhere downstream, so the field stays
                                // empty and shows no placeholder.
                                singleLine = true,
                                // Reserves the chevron's column, so the display
                                // name ends exactly where the model id input ends.
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(end = MODEL_TOGGLE_WIDTH)
                                    .onFocusChanged {
                                        if (it.isFocused) focusTarget(MODEL_FIELD_NAME)
                                    }
                            )
                            Spacer(Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.Top
                            ) {
                                // The limit pair stops where the model id input
                                // stops, leaving the trailing column free for the
                                // delete button.
                                Row(
                                    modifier = Modifier.weight(1f),
                                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                                    verticalAlignment = Alignment.Top
                                ) {
                                    OutlinedTextField(
                                        value = model.contextLimitTokens?.toString().orEmpty(),
                                        onValueChange = { value ->
                                            val parsed = value.filter(Char::isDigit).take(7).toIntOrNull()
                                            models = models.mapIndexed { modelIndex, current ->
                                                if (modelIndex == index) current.copy(contextLimitTokens = parsed) else current
                                            }
                                        },
                                        label = { Text(stringResource(R.string.agent_model_context_limit)) },
                                        singleLine = true,
                                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                        modifier = Modifier.weight(1f).onFocusChanged {
                                            if (it.isFocused) focusTarget(MODEL_FIELD_CONTEXT_LIMIT)
                                        }
                                    )
                                    OutlinedTextField(
                                        value = model.outputLimitTokens?.toString().orEmpty(),
                                        onValueChange = { value ->
                                            val parsed = value.filter(Char::isDigit).take(7).toIntOrNull()
                                            models = models.mapIndexed { modelIndex, current ->
                                                if (modelIndex == index) current.copy(outputLimitTokens = parsed) else current
                                            }
                                        },
                                        label = { Text(stringResource(R.string.agent_model_output_limit)) },
                                        singleLine = true,
                                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                        modifier = Modifier.weight(1f).onFocusChanged {
                                            if (it.isFocused) focusTarget(MODEL_FIELD_OUTPUT_LIMIT)
                                        }
                                    )
                                }
                                // Delete occupies the same trailing column as the
                                // chevron, so the two icons line up.
                                IconButton(
                                    onClick = {
                                        focusManager.clearFocus()
                                        models = models.filterIndexed { modelIndex, _ -> modelIndex != index }
                                    },
                                    enabled = models.size > 1,
                                    modifier = Modifier.size(MODEL_TOGGLE_WIDTH)
                                ) {
                                    Icon(
                                        Icons.Default.Delete,
                                        contentDescription = stringResource(R.string.agent_delete_model)
                                    )
                                }
                            }
                            if (provider.id != AgentSettings.LOCAL_PROVIDER_ID) {
                                Box {
                                    TextButton(onClick = { reasoningEffortMenuIndex = index }) {
                                        Text(
                                            stringResource(
                                                R.string.agent_reasoning_effort_value,
                                                reasoningEffortLabel(model.reasoningEffort)
                                            )
                                        )
                                    }
                                    DropdownMenu(
                                        expanded = reasoningEffortMenuIndex == index,
                                        onDismissRequest = { reasoningEffortMenuIndex = null }
                                    ) {
                                        AgentReasoningEffort.values().forEach { option ->
                                            DropdownMenuItem(
                                                text = { Text(reasoningEffortLabel(option)) },
                                                onClick = {
                                                    models = models.mapIndexed { modelIndex, current ->
                                                        if (modelIndex == index) {
                                                            current.copy(reasoningEffort = option)
                                                        } else {
                                                            current
                                                        }
                                                    }
                                                    reasoningEffortMenuIndex = null
                                                }
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                items(fetchedModelIds, key = { it }) { modelId ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = fetchedSelection[modelId] == true,
                            onCheckedChange = { fetchedSelection[modelId] = it }
                        )
                        Text(
                            text = modelId,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
                if (fetchedModelIds.isNotEmpty()) {
                    item {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            val selectedCount = fetchedSelection.count { it.value }
                            TextButton(
                                onClick = {
                                    val newlyAdded = fetchedSelection
                                        .filterValues { it }
                                        .keys
                                        .filterNot { id -> models.any { it.id == id } }
                                    if (newlyAdded.isNotEmpty()) {
                                        // Name stays empty on purpose: a fetched
                                        // id is enough, and the editor then shows
                                        // the id as the effective label.
                                        models = models + newlyAdded.map { AgentModelConfig(id = it) }
                                    }
                                    fetchedModelIds = fetchedModelIds - newlyAdded
                                    fetchedSelection.clear()
                                },
                                enabled = selectedCount > 0
                            ) {
                                Text(
                                    stringResource(
                                        R.string.agent_fetch_models_add_selected,
                                        selectedCount
                                    )
                                )
                            }
                            TextButton(
                                onClick = {
                                    fetchedModelIds = emptyList()
                                    fetchedSelection.clear()
                                    fetchFailure = null
                                }
                            ) {
                                Text(stringResource(R.string.agent_fetch_models_dismiss))
                            }
                        }
                    }
                }
                item {
                    TextButton(
                        onClick = { models += AgentModelConfig(id = "", name = "") }
                    ) {
                        Icon(Icons.Default.Add, contentDescription = null)
                        Spacer(Modifier.width(6.dp))
                        Text(stringResource(R.string.agent_add_model))
                    }
                    if (byokEnabled && provider.id != AgentSettings.LOCAL_PROVIDER_ID) {
                        HorizontalDivider(Modifier.padding(vertical = 4.dp))
                        Text(
                            text = if (provider.apiKeyConfigured) {
                                stringResource(R.string.agent_byok_configured)
                            } else {
                                stringResource(R.string.agent_byok_not_configured)
                            },
                            style = MaterialTheme.typography.bodySmall
                        )
                        OutlinedTextField(
                            value = apiKey,
                            onValueChange = { apiKey = it },
                            label = { Text(stringResource(R.string.agent_byok_key)) },
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                            modifier = Modifier.fillMaxWidth()
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            TextButton(
                                onClick = {
                                    // Persist the fields as currently edited, not the
                                    // stale open-time draft, so a provider created and
                                    // keyed in one pass keeps its typed name.
                                    onSaveProviderKey(
                                        editedProviderDraft(
                                            provider,
                                            name,
                                            baseUrl,
                                            models,
                                            apiType,
                                            chatResponseFormat
                                        ),
                                        apiKey
                                    )
                                    apiKey = ""
                                },
                                enabled = apiKey.isNotBlank()
                            ) {
                                Icon(Icons.Default.Key, contentDescription = null)
                                Spacer(Modifier.width(4.dp))
                                Text(stringResource(R.string.agent_byok_save))
                            }
                            TextButton(
                                onClick = { onClearProviderKey(provider.id) },
                                enabled = provider.apiKeyConfigured
                            ) {
                                Text(stringResource(R.string.agent_byok_clear))
                            }
                        }
                    } else if (!byokEnabled && provider.id != AgentSettings.LOCAL_PROVIDER_ID) {
                        Text(
                            stringResource(R.string.agent_byok_release_notice),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onSave(
                        editedProviderDraft(
                            provider,
                            name,
                            baseUrl,
                            models,
                            apiType,
                            chatResponseFormat
                        )
                    )
                },
                enabled = canSave
            ) {
                Text(stringResource(R.string.save))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}

@Composable
private fun ExpandedModelFieldDialog(
    label: String,
    value: String,
    onDismiss: () -> Unit,
    onSave: (String) -> Unit
) {
    var draft by remember { mutableStateOf(value) }
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier.padding(16.dp).widthIn(max = 640.dp).fillMaxWidth(),
            shape = MaterialTheme.shapes.extraLarge,
            tonalElevation = 6.dp
        ) {
            Column(
                modifier = Modifier.padding(24.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text(label, style = MaterialTheme.typography.headlineSmall)
                OutlinedTextField(
                    value = draft,
                    // Wrap for readability, but keep configuration values single-line.
                    onValueChange = { draft = it.replace("\r", "").replace("\n", "") },
                    label = { Text(label) },
                    minLines = 3,
                    maxLines = 4,
                    modifier = Modifier.fillMaxWidth()
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
                    TextButton(onClick = { onSave(draft) }) { Text(stringResource(R.string.save)) }
                }
            }
        }
    }
}

/**
 * The provider as currently edited. Out-of-range token limits are dropped
 * instead of thrown so the key-save path (not gated by the form validation)
 * can never crash the settings store.
 */
private fun editedProviderDraft(
    provider: AgentProviderConfig,
    name: String,
    baseUrl: String,
    models: List<AgentModelConfig>,
    apiType: AgentApiType,
    chatResponseFormat: AgentChatResponseFormat
): AgentProviderConfig = provider.copy(
    name = name.trim(),
    baseUrl = baseUrl.trim().trimEnd('/'),
    models = models
        .map { model ->
            model.copy(
                contextLimitTokens = model.contextLimitTokens?.takeIf {
                    it in AgentModelConfig.MIN_CONTEXT_LIMIT_TOKENS..
                        AgentModelConfig.MAX_CONTEXT_LIMIT_TOKENS
                },
                outputLimitTokens = model.outputLimitTokens?.takeIf {
                    it in AgentModelConfig.MIN_OUTPUT_LIMIT_TOKENS..
                        AgentModelConfig.MAX_OUTPUT_LIMIT_TOKENS
                }
            )
        }
        .map(AgentModelConfig::normalized)
        .filter { it.id.isNotBlank() }
        .distinctBy { it.id },
    apiType = apiType,
    chatResponseFormat = chatResponseFormat
)
