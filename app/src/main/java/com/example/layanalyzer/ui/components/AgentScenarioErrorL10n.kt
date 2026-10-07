// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.example.layanalyzer.R
import com.example.layanalyzer.ai.playbook.ScenarioValidationCodes
import com.example.layanalyzer.ai.playbook.ScenarioValidationError

/**
 * Localization surface for scenario validation rejections (OPT-ERR-01).
 *
 * The data layer reports rejections as stable reason codes
 * ([ScenarioValidationError] — code plus args, never prose); this file owns
 * the single code → string-resource map the editor uses everywhere: inline
 * field errors, the save-rejection summary card, and (via the same codes)
 * any future surface.  An unrecognized code resolves to no resource and the
 * UI shows the raw code instead — debuggable, never crashing, and never
 * silently dropping an error.  [scenarioErrorCodeResId] is a plain function
 * so JVM tests can pin the mapping's coverage without Compose.
 */

/**
 * The string resource for one validation reason code, or `null` when the
 * mapping does not know the code (the caller then shows the code verbatim).
 */
@StringRes
internal fun scenarioErrorCodeResId(code: String): Int? = when (code) {
    ScenarioValidationCodes.ID_BUILTIN_CONFLICT ->
        R.string.agent_scenario_editor_error_id_builtin_conflict
    ScenarioValidationCodes.ID_PREFIX_REQUIRED ->
        R.string.agent_scenario_editor_error_id_prefix_required
    ScenarioValidationCodes.INTENT_HINTS_REQUIRED ->
        R.string.agent_scenario_editor_error_intent_hints_required
    ScenarioValidationCodes.TEXT_TOO_LONG ->
        R.string.agent_scenario_editor_error_text_too_long
    ScenarioValidationCodes.TEXT_FORBIDDEN_CONTENT ->
        R.string.agent_scenario_editor_error_text_not_declarative
    ScenarioValidationCodes.REQUIRED_FIELDS_CAP ->
        R.string.agent_scenario_editor_required_fields_cap
    ScenarioValidationCodes.TOOL_NOT_ALLOWED ->
        R.string.agent_scenario_editor_error_tool_not_allowed
    ScenarioValidationCodes.FIELD_NOT_SUPPORTED ->
        R.string.agent_scenario_editor_error_field_not_supported
    ScenarioValidationCodes.ID_INVALID ->
        R.string.agent_scenario_editor_error_id_invalid
    ScenarioValidationCodes.VERSION_NOT_POSITIVE ->
        R.string.agent_scenario_editor_error_version_not_positive
    ScenarioValidationCodes.INITIAL_TOOLS_EMPTY ->
        R.string.agent_scenario_editor_error_initial_tools_empty
    ScenarioValidationCodes.UNKNOWN_PROPERTIES ->
        R.string.agent_scenario_editor_error_unknown_properties
    ScenarioValidationCodes.MISSING_PROPERTIES ->
        R.string.agent_scenario_editor_error_missing_properties
    ScenarioValidationCodes.STRING_BLANK ->
        R.string.agent_scenario_editor_error_string_blank
    ScenarioValidationCodes.EXPECTED_NUMBER ->
        R.string.agent_scenario_editor_error_expected_number
    ScenarioValidationCodes.EXPECTED_OBJECT ->
        R.string.agent_scenario_editor_error_expected_object
    ScenarioValidationCodes.EXPECTED_ARRAY ->
        R.string.agent_scenario_editor_error_expected_array
    ScenarioValidationCodes.LIST_TOO_LONG ->
        R.string.agent_scenario_editor_error_list_too_long
    ScenarioValidationCodes.SCHEMA_VERSION_UNSUPPORTED ->
        R.string.agent_scenario_editor_error_schema_version_unsupported
    ScenarioValidationCodes.DUPLICATE_IDS ->
        R.string.agent_scenario_editor_error_duplicate_ids
    ScenarioValidationCodes.STRUCTURAL_REJECTION ->
        R.string.agent_scenario_editor_error_structural_rejection
    ScenarioValidationCodes.TEXT_REJECTED ->
        R.string.agent_scenario_editor_error_text_rejected
    else -> null
}

/**
 * The localized message for one [ScenarioValidationError].  Codes with
 * formatting args (text length/caps take `max`, tool and field name their
 * offender, property lists `properties`, the schema version `version`) are
 * resolved with those args; a missing or malformed arg — like an unknown
 * code — falls back to showing the raw code so nothing ever renders blank
 * or crashes.
 */
@Composable
internal fun agentScenarioValidationErrorMessage(error: ScenarioValidationError): String {
    @StringRes val resId = scenarioErrorCodeResId(error.code) ?: return error.code
    return when (resId) {
        R.string.agent_scenario_editor_error_text_too_long,
        R.string.agent_scenario_editor_required_fields_cap,
        R.string.agent_scenario_editor_error_list_too_long ->
            error.args["max"]?.toIntOrNull()?.let { stringResource(resId, it) } ?: error.code
        R.string.agent_scenario_editor_error_tool_not_allowed ->
            error.args["tool"]?.let { stringResource(resId, it) } ?: error.code
        R.string.agent_scenario_editor_error_field_not_supported ->
            error.args["field"]?.let { stringResource(resId, it) } ?: error.code
        R.string.agent_scenario_editor_error_unknown_properties,
        R.string.agent_scenario_editor_error_missing_properties ->
            error.args["properties"]?.let { stringResource(resId, it) } ?: error.code
        R.string.agent_scenario_editor_error_schema_version_unsupported ->
            error.args["version"]?.let { stringResource(resId, it) } ?: error.code
        else -> stringResource(resId)
    }
}
