// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.layanalyzer.R
import com.example.layanalyzer.ai.playbook.AgentPlaybook
import com.example.layanalyzer.ai.playbook.AgentPlaybookCheck
import com.example.layanalyzer.ai.playbook.AgentPlaybookFailureBranch
import com.example.layanalyzer.ai.playbook.AgentPlaybookStore
import com.example.layanalyzer.ai.playbook.ScenarioOrigin
import com.example.layanalyzer.ai.playbook.ScenarioTextRules
import com.example.layanalyzer.ai.playbook.ScenarioValidationError
import com.example.layanalyzer.ai.playbook.UserScenarioStore
import com.example.layanalyzer.viewmodel.AgentScenarioDraft
import kotlin.math.roundToInt

/** Trailing marker [com.example.layanalyzer.ai.playbook.UserScenarioPlaybookStore.generateCopyId] appends to copied scenario ids. */
private const val COPY_ID_SUFFIX = "-copy"

/** The id shape [nextCheckId] mints and the Checks editor displays verbatim. */
private const val CHECK_ID_PREFIX = "check-"

/**
 * The full-screen scenario editor (SRE-EDITOR-01, save flow SRE-EDITOR-06).
 *
 * One dialog hosts both modes off the same [AgentScenarioDraft]:
 *
 *  - the editable draft mode (new or user-owned scenario).  All ten sections —
 *    Basic info and Intent hints (SRE-EDITOR-02), Initial tools and Required
 *    fields (SRE-EDITOR-03), Checks, Success path and Failure branches
 *    (SRE-EDITOR-04), and Protocols, Limitations and Report sections
 *    (SRE-EDITOR-05) — validate as the user types and surface the store's own
 *    rejections inline; a rejected save also raises the summary card above the
 *    sections, listing every field path that needs attention, and scrolls the
 *    first rejected field into view (focusing it when it is a text field);
 *  - the read-only details mode opened from the chip long-press menu, which
 *    renders the playbook exactly as stored, skipping sections that hold no
 *    content.
 *
 * The bottom action bar wires the save path
 * ([com.example.layanalyzer.viewmodel.ProtocolAgentViewModel.saveScenario])
 * through [onSave]: the ViewModel saves the draft it already holds — this
 * screen keeps no playbook of its own — and saving is asynchronous and needs
 * no local loading state: a field rejection or a failed write keeps the
 * editor open with the errors written back, while success closes it and the
 * host page raises the saved notice.  Repeat taps while the IO runs are
 * refused by the ViewModel (OPT-SAVE-01); [savingScenario] is that in-flight
 * flag, surfaced here only to disable the Save button for the duration — the
 * refusal itself stays the ViewModel's authority.
 */
@Composable
fun AgentScenarioEditorScreen(
    draft: AgentScenarioDraft,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    /**
     * Persists the draft as currently edited (SRE-EDITOR-06).  Fire-and-
     * forget: the outcome comes back through [AgentScenarioDraft.validationErrors]
     * (editor stays open) or the editor closing (saved).  It carries no
     * playbook because the ViewModel's draft is the single source — every
     * field change has already been reported through [onPlaybookChange].
     */
    onSave: () -> Unit = {},
    /**
     * OPT-SAVE-01: true while the ViewModel has a scenario save in flight.
     * The Save button disables itself for the duration, mirroring the
     * ViewModel's refusal of repeat taps — the button affordance is cosmetic,
     * the ViewModel stays the authority on what a tap may start.
     */
    savingScenario: Boolean = false,
    /**
     * Reports an edited playbook back to the ViewModel draft (OPT-DRAFT-01),
     * the controlled-input counterpart of rendering [AgentScenarioDraft.playbook]:
     * this composable never keeps a copy of its own, so an activity
     * recreation — a rotation — recollects the draft and finds the typed
     * content intact.
     */
    onPlaybookChange: (AgentPlaybook) -> Unit = {},
    /**
     * The host tool whitelist the Initial tools chips offer (SRE-EDITOR-03).
     * It is the same set the save boundary validates against, so a selectable
     * chip is exactly a tool a save accepts; empty renders no chips.
     */
    toolWhitelist: Set<String> = emptySet(),
    /**
     * The host's merged scenario list, used only to resolve a copied
     * scenario's source label (OPT-COPY-01): the source id becomes the
     * source's title when it is still in the list and stays the bare id
     * otherwise.  Empty renders the id fallback.
     */
    playbooks: List<AgentPlaybook> = emptyList()
) {
    // No local playbook copy: every field renders draft.playbook (the live
    // draft) and compares against draft.validatedPlaybook (the frozen
    // snapshot the store last rejected), both read straight from the
    // ViewModel-owned draft.

    // Scroll-to-first-error anchors (SRE-EDITOR-06): the scroll container's
    // top and each section's top, both in root coordinates.  Read as a pair
    // at scroll time, the difference is the section's position in the viewport
    // whatever the summary card insertion shifted in the meantime.
    val scrollState = rememberScrollState()
    var scrollContainerTop by remember { mutableStateOf(0) }
    val sectionTops = remember { mutableStateMapOf<ScenarioEditorSection, Int>() }
    val errorScrollMarginPx = with(LocalDensity.current) {
        ScenarioErrorScrollMargin.roundToPx()
    }

    // A rejected save brings the first rejected field into view.  Keyed on the
    // errors' content, so the draft the ViewModel writes back after a save
    // (same map content every time it did not change) re-runs this only when
    // the rejection actually changed.  The ViewModel never opens a read-only
    // draft with errors, so this never scrolls in details mode.
    LaunchedEffect(draft.validationErrors) {
        val firstPath = draft.validationErrors.keys.firstOrNull() ?: return@LaunchedEffect
        val section = scenarioErrorSection(firstPath)
        // The summary card insertion shifts every section down; two frame
        // ticks resume after the next layout pass has re-reported the
        // positions, so the anchors describe the shifted content.
        withFrameNanos { }
        withFrameNanos { }
        runCatching {
            val sectionTop = sectionTops[section]
            when {
                section == ScenarioEditorSection.Summary || sectionTop == null ->
                    // Header-level (`id`) and unknown paths anchor to the top,
                    // where the summary card sits.
                    scrollState.animateScrollTo(0)
                else -> scrollState.animateScrollTo(
                    (
                        scrollState.value + sectionTop - scrollContainerTop -
                            errorScrollMarginPx
                        ).coerceAtLeast(0)
                )
            }
        }
    }

    val title = when {
        draft.readOnly -> stringResource(R.string.agent_scenario_editor_title_details)
        draft.isNew -> stringResource(R.string.agent_scenario_editor_title_new)
        else -> stringResource(R.string.agent_scenario_editor_title_edit)
    }
    val sourceLabel = when {
        draft.readOnly && draft.playbook.origin == ScenarioOrigin.BuiltIn ->
            stringResource(R.string.agent_scenario_editor_source_builtin)
        draft.playbook.origin == ScenarioOrigin.User -> {
            // OPT-COPY-01: a copy is labelled with its source's title, not
            // the bare internal id; the id remains the fallback when the
            // source left the list (deleted, or a retired built-in id).
            val copySource = scenarioCopySourceLabel(draft.playbook.id, playbooks)
            if (copySource != null) {
                stringResource(R.string.agent_scenario_editor_source_copied, copySource)
            } else {
                stringResource(R.string.agent_scenario_editor_source_user)
            }
        }
        else -> stringResource(R.string.agent_scenario_editor_source_builtin)
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            decorFitsSystemWindows = false
        )
    ) {
        Surface(
            color = MaterialTheme.colorScheme.background,
            modifier = modifier.fillMaxSize()
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .systemBarsPadding()
                    .imePadding()
            ) {
                AgentScenarioEditorTopBar(
                    title = title,
                    onDismiss = onDismiss
                )
                HorizontalDivider()
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        // The container anchor sits outside the scroll
                        // modifier, so its root position stays fixed while
                        // the content scrolls; paired with a section's root
                        // position it yields the section's viewport offset.
                        .onGloballyPositioned { coords ->
                            scrollContainerTop = coords.positionInRoot().y.roundToInt()
                        }
                        .verticalScroll(scrollState)
                        .padding(horizontal = 16.dp, vertical = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    AgentScenarioEditorHeader(
                        draft = draft,
                        sourceLabel = sourceLabel
                    )
                    if (draft.readOnly) {
                        AgentScenarioReadOnlySections(draft.playbook)
                    } else {
                        // The save-rejection summary sits at the top of the
                        // edit content, before every section; the read-only
                        // mode never renders one because it cannot save.
                        AgentScenarioErrorSummaryCard(validationErrors = draft.validationErrors)
                        AgentScenarioEditorEditSections(
                            draft = draft,
                            toolWhitelist = toolWhitelist,
                            onPlaybookChange = onPlaybookChange,
                            onSectionPositioned = { section, top ->
                                sectionTops[section] = top
                            }
                        )
                    }
                }
                AgentScenarioEditorBottomBar(
                    readOnly = draft.readOnly,
                    onDismiss = onDismiss,
                    // Everything the user typed is already in the draft, so
                    // the save request carries nothing.
                    onSave = onSave,
                    savingScenario = savingScenario
                )
            }
        }
    }
}

/** How far above the viewport top a scrolled-to error section rests. */
private val ScenarioErrorScrollMargin = 24.dp

/**
 * The bottom action bar (SRE-EDITOR-06), styled after the top bar: a divider
 * over a plain row inside the dialog's [Surface].  Edit mode offers Cancel —
 * which only closes and never persists, the draft being memory-only until a
 * successful save — and Save; read-only mode offers only Close.  The bar sits
 * inside the dialog's `imePadding` column, so the keyboard pushes it above
 * itself instead of covering it.  Save disables while a save is in flight
 * (OPT-SAVE-01), the same window in which the ViewModel drops repeat taps.
 */
@Composable
private fun AgentScenarioEditorBottomBar(
    readOnly: Boolean,
    onDismiss: () -> Unit,
    onSave: () -> Unit,
    savingScenario: Boolean
) {
    HorizontalDivider()
    Surface(color = MaterialTheme.colorScheme.background) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Spacer(Modifier.weight(1f))
            if (readOnly) {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.agent_scenario_editor_close))
                }
            } else {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.cancel))
                }
                Button(
                    onClick = onSave,
                    enabled = !savingScenario
                ) {
                    Text(stringResource(R.string.agent_scenario_editor_save))
                }
            }
        }
    }
}

/**
 * The save-rejection summary card (SRE-EDITOR-05), shown above every section
 * while the last save attempt rejected the draft.  Each entry pairs the
 * user-facing label for the rejected field path ([scenarioErrorPathLabel],
 * shown verbatim when the mapping does not know the path) with the localized
 * message for the store's reason code
 * ([agentScenarioValidationErrorMessage], which falls back to the raw code
 * for anything unmapped), so the summary and the inline field errors always
 * describe the same rejection in the same words.
 */
@Composable
private fun AgentScenarioErrorSummaryCard(
    validationErrors: Map<String, ScenarioValidationError>
) {
    if (validationErrors.isEmpty()) return
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(
                text = stringResource(
                    R.string.agent_scenario_editor_error_summary_title,
                    validationErrors.size
                ),
                style = MaterialTheme.typography.titleSmall
            )
            validationErrors.forEach { (path, error) ->
                Text(
                    text = stringResource(
                        R.string.agent_scenario_editor_error_summary_entry,
                        agentScenarioErrorPathLabelOrRaw(path),
                        agentScenarioValidationErrorMessage(error)
                    ),
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

/** Resolves one summary-bar path to its user-facing label, or shows it raw. */
@Composable
private fun agentScenarioErrorPathLabelOrRaw(path: String): String {
    val label = scenarioErrorPathLabel(path) ?: return path
    return stringResource(label.resId, *label.args.toTypedArray())
}

@Composable
private fun AgentScenarioEditorTopBar(
    title: String,
    onDismiss: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 4.dp, end = 16.dp, top = 4.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        IconButton(onClick = onDismiss) {
            Icon(
                imageVector = Icons.Filled.Close,
                contentDescription = stringResource(R.string.agent_scenario_editor_close)
            )
        }
        Text(
            text = title,
            style = MaterialTheme.typography.titleLarge,
            maxLines = 1,
            modifier = Modifier.weight(1f)
        )
    }
}

/** The provenance line and the read-only identity line, shared by both modes. */
@Composable
private fun AgentScenarioEditorHeader(
    draft: AgentScenarioDraft,
    sourceLabel: String
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            text = sourceLabel,
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.primary
        )
        if (draft.isNew) {
            // An unsaved scenario has neither id nor version: both are
            // minted by the user scenario layer at save time.
            Text(
                text = stringResource(R.string.agent_scenario_editor_not_saved),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            Text(
                text = draft.playbook.versionedId,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * Editable mode: all ten field sections — Basic info and Intent hints
 * (SRE-EDITOR-02), Initial tools and Required fields (SRE-EDITOR-03), Checks,
 * Success path and Failure branches (SRE-EDITOR-04), and Protocols,
 * Limitations and Report sections (SRE-EDITOR-05).
 *
 * Every field renders [AgentScenarioDraft.playbook] — the live draft, never
 * a local copy (OPT-DRAFT-01) — and computes one `errorText`: the shared
 * [scenarioFieldErrorText] lookup — the localized message for the store's
 * reason code on that field path wins while the field still holds the value
 * the store rejected, read from [AgentScenarioDraft.validatedPlaybook] — is
 * tried first; otherwise the real-time validation below runs, so typing
 * feedback never waits for a save.
 */
@Composable
private fun AgentScenarioEditorEditSections(
    draft: AgentScenarioDraft,
    toolWhitelist: Set<String>,
    onPlaybookChange: (AgentPlaybook) -> Unit,
    /** SRE-EDITOR-06: reports each section's top as it is laid out. */
    onSectionPositioned: (ScenarioEditorSection, Int) -> Unit
) {
    // One positioned modifier per section: the reported root y is the anchor
    // the scroll-to-first-error logic scrolls to.
    val positioned: (ScenarioEditorSection) -> Modifier = { section ->
        Modifier.onGloballyPositioned { coords ->
            onSectionPositioned(section, coords.positionInRoot().y.roundToInt())
        }
    }
    AgentScenarioEditorSection(
        title = stringResource(R.string.agent_scenario_editor_section_basic_info),
        description = stringResource(R.string.agent_scenario_editor_desc_basic_info),
        modifier = positioned(ScenarioEditorSection.BasicInfo)
    ) {
        AgentScenarioTitleField(
            draft = draft,
            onPlaybookChange = onPlaybookChange
        )
    }
    AgentScenarioEditorSection(
        title = stringResource(R.string.agent_scenario_editor_section_intent_hints),
        description = stringResource(R.string.agent_scenario_editor_desc_intent_hints),
        modifier = positioned(ScenarioEditorSection.IntentHints)
    ) {
        AgentScenarioIntentHintsEditor(
            draft = draft,
            onPlaybookChange = onPlaybookChange
        )
    }
    AgentScenarioEditorSection(
        title = stringResource(R.string.agent_scenario_editor_section_initial_tools),
        description = stringResource(R.string.agent_scenario_editor_desc_initial_tools),
        modifier = positioned(ScenarioEditorSection.InitialTools)
    ) {
        AgentScenarioInitialToolsEditor(
            draft = draft,
            toolWhitelist = toolWhitelist,
            onPlaybookChange = onPlaybookChange
        )
    }
    AgentScenarioEditorSection(
        title = stringResource(R.string.agent_scenario_editor_section_required_fields),
        description = stringResource(R.string.agent_scenario_editor_desc_required_fields),
        modifier = positioned(ScenarioEditorSection.RequiredFields)
    ) {
        AgentScenarioRequiredFieldsEditor(
            draft = draft,
            onPlaybookChange = onPlaybookChange
        )
    }
    AgentScenarioEditorSection(
        title = stringResource(R.string.agent_scenario_editor_section_checks),
        description = stringResource(R.string.agent_scenario_editor_desc_checks),
        modifier = positioned(ScenarioEditorSection.Checks)
    ) {
        AgentScenarioChecksEditor(
            draft = draft,
            toolWhitelist = toolWhitelist,
            onPlaybookChange = onPlaybookChange
        )
    }
    AgentScenarioEditorSection(
        title = stringResource(R.string.agent_scenario_editor_section_success_path),
        description = stringResource(R.string.agent_scenario_editor_desc_success_path),
        modifier = positioned(ScenarioEditorSection.SuccessPath)
    ) {
        AgentScenarioSuccessPathEditor(
            draft = draft,
            onPlaybookChange = onPlaybookChange
        )
    }
    AgentScenarioEditorSection(
        title = stringResource(R.string.agent_scenario_editor_section_failure_branches),
        description = stringResource(R.string.agent_scenario_editor_desc_failure_branches),
        modifier = positioned(ScenarioEditorSection.FailureBranches)
    ) {
        AgentScenarioFailureBranchesEditor(
            draft = draft,
            toolWhitelist = toolWhitelist,
            onPlaybookChange = onPlaybookChange
        )
    }
    AgentScenarioEditorSection(
        title = stringResource(R.string.agent_scenario_editor_section_protocols),
        description = stringResource(R.string.agent_scenario_editor_desc_protocols),
        modifier = positioned(ScenarioEditorSection.Protocols)
    ) {
        AgentScenarioProtocolsEditor(
            draft = draft,
            onPlaybookChange = onPlaybookChange
        )
    }
    AgentScenarioEditorSection(
        title = stringResource(R.string.agent_scenario_editor_section_limitations),
        description = stringResource(R.string.agent_scenario_editor_desc_limitations),
        modifier = positioned(ScenarioEditorSection.Limitations)
    ) {
        AgentScenarioLimitationsEditor(
            draft = draft,
            onPlaybookChange = onPlaybookChange
        )
    }
    AgentScenarioEditorSection(
        title = stringResource(R.string.agent_scenario_editor_section_report_sections),
        description = stringResource(R.string.agent_scenario_editor_desc_report_sections),
        modifier = positioned(ScenarioEditorSection.OutputSections)
    ) {
        AgentScenarioOutputSectionsEditor(
            draft = draft,
            onPlaybookChange = onPlaybookChange
        )
    }
}

/**
 * The Protocols editor (SRE-EDITOR-05): protocol scope hints such as `sip` or
 * `rtp`, with `any` declaring no restriction.  Entries are optional
 * declarative text under the shared budget — the same rules the store applies
 * to every other free-text list — and the store's whole-list rejection (the
 * structural gate reports it on the `protocols` path) shows under the rows
 * while it still describes the list on screen.
 */
@Composable
private fun AgentScenarioProtocolsEditor(
    draft: AgentScenarioDraft,
    onPlaybookChange: (AgentPlaybook) -> Unit
) {
    val playbook = draft.playbook
    AgentScenarioTextListEditor(
        draft = draft,
        entries = playbook.protocols,
        validatedEntries = draft.validatedPlaybook?.protocols,
        listPath = "protocols",
        sectionHintRes = R.string.agent_scenario_editor_protocols_hint,
        placeholderRes = R.string.agent_scenario_editor_protocol_hint,
        addLabelRes = R.string.agent_scenario_editor_add_protocol,
        removeLabelRes = R.string.agent_scenario_editor_remove_protocol,
        onEntriesChange = { onPlaybookChange(playbook.copy(protocols = it)) }
    )
}

/**
 * The Limitations editor (SRE-EDITOR-05): the constraints a saved report must
 * state, stored as `requiredLimitations`.  Same optional-text list editor; the
 * store rejects over-long or non-declarative entries on the
 * `requiredLimitations[i]` paths, which the rows surface inline.
 */
@Composable
private fun AgentScenarioLimitationsEditor(
    draft: AgentScenarioDraft,
    onPlaybookChange: (AgentPlaybook) -> Unit
) {
    val playbook = draft.playbook
    AgentScenarioTextListEditor(
        draft = draft,
        entries = playbook.requiredLimitations,
        validatedEntries = draft.validatedPlaybook?.requiredLimitations,
        listPath = "requiredLimitations",
        sectionHintRes = R.string.agent_scenario_editor_limitations_hint,
        placeholderRes = R.string.agent_scenario_editor_limitation_entry_hint,
        addLabelRes = R.string.agent_scenario_editor_add_limitation,
        removeLabelRes = R.string.agent_scenario_editor_remove_limitation,
        onEntriesChange = { onPlaybookChange(playbook.copy(requiredLimitations = it)) }
    )
}

/**
 * The Report sections editor (SRE-EDITOR-05): the names of the sections the
 * saved report should fill, stored as `outputSections`.  Same optional-text
 * list editor; the store rejects entries on the `outputSections[i]` paths.
 */
@Composable
private fun AgentScenarioOutputSectionsEditor(
    draft: AgentScenarioDraft,
    onPlaybookChange: (AgentPlaybook) -> Unit
) {
    val playbook = draft.playbook
    AgentScenarioTextListEditor(
        draft = draft,
        entries = playbook.outputSections,
        validatedEntries = draft.validatedPlaybook?.outputSections,
        listPath = "outputSections",
        sectionHintRes = R.string.agent_scenario_editor_report_sections_hint,
        placeholderRes = R.string.agent_scenario_editor_report_section_hint,
        addLabelRes = R.string.agent_scenario_editor_add_report_section,
        removeLabelRes = R.string.agent_scenario_editor_remove_report_section,
        onEntriesChange = { onPlaybookChange(playbook.copy(outputSections = it)) }
    )
}

/**
 * The plain string-list editor shared by the Protocols, Limitations and Report
 * sections editors (SRE-EDITOR-05): the Intent hints / Success path row
 * pattern — one optional field per row with the shared text budget and
 * declarative rule, appended and removed in place so the order the user built
 * is never reshuffled, a freshly appended row focused on add.  Rows show the
 * store's own rejection for their `listPath[index]` while the text is
 * unchanged, the whole list shows the store's rejection for `listPath` itself,
 * and a `n/limit` counter keeps the budget visible on healthy rows.
 */
@Composable
private fun AgentScenarioTextListEditor(
    draft: AgentScenarioDraft,
    entries: List<String>,
    /** The same list as the store last rejected, or null before a rejection. */
    validatedEntries: List<String>?,
    listPath: String,
    sectionHintRes: Int,
    placeholderRes: Int,
    addLabelRes: Int,
    removeLabelRes: Int,
    onEntriesChange: (List<String>) -> Unit
) {
    val maxLength = ScenarioTextRules.USER_MAX_TEXT_LENGTH
    // Best-effort focus handoff: the index of the row that should take focus
    // once it exists, cleared by whichever row claims it.
    var pendingFocusIndex by remember { mutableStateOf(-1) }
    // SRE-EDITOR-06: a save rejection naming one of this list's rows claims
    // the same handoff so the offending entry is focused as well as scrolled to.
    LaunchedEffect(draft.validationErrors) {
        val row = draft.validationErrors.keys.firstOrNull()
            ?.let { scenarioErrorListRow(it, listPath) }
        if (row != null) pendingFocusIndex = row
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(sectionHintRes),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        entries.forEachIndexed { index, entry ->
            val rowFocusRequester = remember { FocusRequester() }
            LaunchedEffect(pendingFocusIndex) {
                if (pendingFocusIndex == index) {
                    // The node may not be attached yet on a fast tap; a missed
                    // focus request is cosmetic and safe to drop.
                    runCatching { rowFocusRequester.requestFocus() }
                    pendingFocusIndex = -1
                }
            }
            val errorText = scenarioFieldErrorText(
                validationErrors = draft.validationErrors,
                path = "$listPath[$index]",
                currentValue = entry,
                storedValue = validatedEntries?.getOrNull(index)
            ) ?: agentScenarioOptionalTextError(entry, maxLength)?.let {
                agentScenarioValidationErrorText(it, maxLength)
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = entry,
                    onValueChange = { updated ->
                        onEntriesChange(
                            entries.mapIndexed { position, existing ->
                                if (position == index) updated else existing
                            }
                        )
                    },
                    placeholder = {
                        Text(stringResource(placeholderRes))
                    },
                    isError = errorText != null,
                    singleLine = true,
                    supportingText = if (errorText != null) {
                        {
                            Text(
                                text = errorText,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    } else {
                        {
                            Text(
                                text = stringResource(
                                    R.string.agent_scenario_editor_text_counter,
                                    entry.length,
                                    maxLength
                                ),
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    },
                    modifier = Modifier
                        .weight(1f)
                        .focusRequester(rowFocusRequester)
                )
                IconButton(
                    onClick = {
                        onEntriesChange(
                            entries.filterIndexed { position, _ -> position != index }
                        )
                    }
                ) {
                    Icon(
                        imageVector = Icons.Filled.Delete,
                        contentDescription = stringResource(removeLabelRes)
                    )
                }
            }
        }
        val listError = scenarioFieldErrorText(
            validationErrors = draft.validationErrors,
            path = listPath,
            currentValue = entries,
            storedValue = validatedEntries
        )
        if (listError != null) {
            Text(
                text = listError,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
        }
        TextButton(
            onClick = {
                onEntriesChange(entries + "")
                pendingFocusIndex = entries.size
            }
        ) {
            Icon(Icons.Filled.Add, contentDescription = null)
            Spacer(Modifier.width(6.dp))
            Text(stringResource(addLabelRes))
        }
    }
}

/**
 * The Basic info title editor.  Validates on every keystroke: required, within
 * [ScenarioTextRules.USER_MAX_TITLE_LENGTH], and declarative per the shared
 * text rules.  When no error stands, a `n/limit` counter takes the supporting
 * line so the budget stays visible while typing.
 */
@Composable
private fun AgentScenarioTitleField(
    draft: AgentScenarioDraft,
    onPlaybookChange: (AgentPlaybook) -> Unit
) {
    val playbook = draft.playbook
    val maxLength = ScenarioTextRules.USER_MAX_TITLE_LENGTH
    val errorText = scenarioFieldErrorText(
        validationErrors = draft.validationErrors,
        path = "title",
        currentValue = playbook.title,
        storedValue = draft.validatedPlaybook?.title
    ) ?: agentScenarioTitleError(playbook.title, maxLength)?.let {
        agentScenarioValidationErrorText(it, maxLength)
    }
    val titleFocusRequester = remember { FocusRequester() }
    // SRE-EDITOR-06: a save rejection naming the title claims focus after the
    // scroll-to-first-error pass brought the section into view.
    LaunchedEffect(draft.validationErrors) {
        if (draft.validationErrors.keys.firstOrNull() == "title") {
            runCatching { titleFocusRequester.requestFocus() }
        }
    }
    OutlinedTextField(
        value = playbook.title,
        onValueChange = { onPlaybookChange(playbook.copy(title = it)) },
        label = { Text(stringResource(R.string.agent_scenario_editor_title_label)) },
        isError = errorText != null,
        singleLine = true,
        supportingText = {
            if (errorText != null) {
                Text(
                    text = errorText,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            } else {
                Text(
                    text = stringResource(
                        R.string.agent_scenario_editor_title_counter,
                        playbook.title.length,
                        maxLength
                    ),
                    style = MaterialTheme.typography.bodySmall
                )
            }
        },
        modifier = Modifier
            .fillMaxWidth()
            .focusRequester(titleFocusRequester)
    )
}

/**
 * The Intent hints list editor.  Every row is one hint, edited and removed in
 * place so the order the user built is never reshuffled; a freshly appended
 * row receives focus so "Add intent hint" reads as one motion.  The section
 * itself flags the empty list — the store rejects a save without any hint.
 */
@Composable
private fun AgentScenarioIntentHintsEditor(
    draft: AgentScenarioDraft,
    onPlaybookChange: (AgentPlaybook) -> Unit
) {
    val playbook = draft.playbook
    val maxLength = ScenarioTextRules.USER_MAX_HINT_LENGTH
    val hints = playbook.intentHints
    // Best-effort focus handoff: the index of the row that should take focus
    // once it exists, cleared by whichever row claims it.
    var pendingFocusIndex by remember { mutableStateOf(-1) }
    // SRE-EDITOR-06: a save rejection naming one of this list's rows claims
    // the same handoff, so the offending hint is focused as well as scrolled to.
    LaunchedEffect(draft.validationErrors) {
        val row = draft.validationErrors.keys.firstOrNull()
            ?.let { scenarioErrorListRow(it, "intentHints") }
        if (row != null) pendingFocusIndex = row
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        hints.forEachIndexed { index, hint ->
            val rowFocusRequester = remember { FocusRequester() }
            LaunchedEffect(pendingFocusIndex) {
                if (pendingFocusIndex == index) {
                    // The node may not be attached yet on a fast tap; a missed
                    // focus request is cosmetic and safe to drop.
                    runCatching { rowFocusRequester.requestFocus() }
                    pendingFocusIndex = -1
                }
            }
            val errorText = scenarioFieldErrorText(
                validationErrors = draft.validationErrors,
                path = "intentHints[$index]",
                currentValue = hint,
                storedValue = draft.validatedPlaybook?.intentHints?.getOrNull(index)
            ) ?: agentScenarioHintError(hint, maxLength)?.let {
                agentScenarioValidationErrorText(it, maxLength)
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = hint,
                    onValueChange = { updated ->
                        onPlaybookChange(
                            playbook.copy(
                                intentHints = hints.mapIndexed { position, existing ->
                                    if (position == index) updated else existing
                                }
                            )
                        )
                    },
                    placeholder = {
                        Text(stringResource(R.string.agent_scenario_editor_hint_placeholder))
                    },
                    isError = errorText != null,
                    singleLine = true,
                    supportingText = if (errorText != null) {
                        {
                            Text(
                                text = errorText,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    } else {
                        null
                    },
                    modifier = Modifier
                        .weight(1f)
                        .focusRequester(rowFocusRequester)
                )
                IconButton(
                    onClick = {
                        onPlaybookChange(
                            playbook.copy(
                                intentHints = hints.filterIndexed { position, _ ->
                                    position != index
                                }
                            )
                        )
                    }
                ) {
                    Icon(
                        imageVector = Icons.Filled.Delete,
                        contentDescription = stringResource(
                            R.string.agent_scenario_editor_remove_intent_hint
                        )
                    )
                }
            }
        }
        val sectionError = scenarioFieldErrorText(
            validationErrors = draft.validationErrors,
            path = "intentHints",
            currentValue = hints,
            storedValue = draft.validatedPlaybook?.intentHints
        ) ?: agentScenarioIntentHintsError(hints)?.let { stringResource(it) }
        if (sectionError != null) {
            Text(
                text = sectionError,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
        }
        TextButton(
            onClick = {
                onPlaybookChange(playbook.copy(intentHints = hints + ""))
                pendingFocusIndex = hints.size
            }
        ) {
            Icon(Icons.Filled.Add, contentDescription = null)
            Spacer(Modifier.width(6.dp))
            Text(stringResource(R.string.agent_scenario_editor_add_intent_hint))
        }
    }
}

/**
 * The Initial tools editor (SRE-EDITOR-03): one toggleable chip per whitelisted
 * tool, rendered in whitelist order.  The selection state lives in the playbook
 * itself and never duplicates — toggling an already-selected tool removes it.
 *
 * These are the tools the model starts a run from, so the section carries the
 * shared hint line; no real-time validation is possible here beyond the store's
 * own rejection (a chip set from the whitelist cannot name an unknown tool),
 * so only the store's message surfaces, while it still describes the list.
 */
@Composable
private fun AgentScenarioInitialToolsEditor(
    draft: AgentScenarioDraft,
    toolWhitelist: Set<String>,
    onPlaybookChange: (AgentPlaybook) -> Unit
) {
    val playbook = draft.playbook
    val selected = playbook.initialTools
    val storeError = scenarioFieldErrorText(
        validationErrors = draft.validationErrors,
        path = "initialTools",
        currentValue = selected,
        storedValue = draft.validatedPlaybook?.initialTools
    )
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.agent_scenario_editor_initial_tools_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = stringResource(R.string.agent_scenario_editor_selected_count, selected.size),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        AgentScenarioToolChipGroup(
            toolWhitelist = toolWhitelist,
            selected = selected,
            onToggle = { tool ->
                onPlaybookChange(playbook.copy(initialTools = toggleInitialTool(selected, tool)))
            }
        )
        if (storeError != null) {
            Text(
                text = storeError,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
        }
    }
}

/**
 * The Required fields editor (SRE-EDITOR-03): the audited field vocabulary as a
 * searchable, alphabetical chip list, with the selected fields pinned above the
 * search box as removable chips so the built order stays visible.  The store's
 * cap ([AgentPlaybookStore.MAX_REQUIRED_FIELDS]) is enforced in place: at the
 * cap every unselected chip disables, the count reads `n/cap`, and a hint line
 * says so.  Like Initial tools, only the store's own rejection surfaces here —
 * chips come from the audited table, so nothing unsupported can be picked.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AgentScenarioRequiredFieldsEditor(
    draft: AgentScenarioDraft,
    onPlaybookChange: (AgentPlaybook) -> Unit
) {
    val playbook = draft.playbook
    val cap = AgentPlaybookStore.MAX_REQUIRED_FIELDS
    val selected = playbook.requiredFields
    val atCap = selected.size >= cap
    // Transient search-box text, not editing input: it filters the candidate
    // chips only and never reaches the playbook, so it stays local state
    // (a rotation clearing it is the pre-existing, accepted behavior).
    var search by remember { mutableStateOf("") }
    val candidates = remember(search) {
        AgentPlaybookStore.SUPPORTED_REQUIRED_FIELDS
            .sorted()
            .filter { it.contains(search.trim(), ignoreCase = true) }
    }
    val storeError = scenarioFieldErrorText(
        validationErrors = draft.validationErrors,
        path = "requiredFields",
        currentValue = selected,
        storedValue = draft.validatedPlaybook?.requiredFields
    )
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        if (selected.isNotEmpty()) {
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                selected.forEach { field ->
                    FilterChip(
                        selected = true,
                        onClick = {
                            onPlaybookChange(
                                playbook.copy(requiredFields = selected - field)
                            )
                        },
                        label = {
                            Text(
                                text = field,
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace
                            )
                        },
                        trailingIcon = {
                            Icon(
                                imageVector = Icons.Filled.Close,
                                contentDescription = stringResource(
                                    R.string.agent_scenario_editor_remove_required_field,
                                    field
                                ),
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    )
                }
            }
        }
        OutlinedTextField(
            value = search,
            onValueChange = { search = it },
            placeholder = {
                Text(stringResource(R.string.agent_scenario_editor_required_fields_search))
            },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = stringResource(
                    R.string.agent_scenario_editor_required_fields_count,
                    selected.size,
                    cap
                ),
                style = MaterialTheme.typography.labelLarge,
                color = if (atCap) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                }
            )
            if (atCap) {
                Spacer(Modifier.width(12.dp))
                Text(
                    text = stringResource(
                        R.string.agent_scenario_editor_required_fields_cap,
                        cap
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        if (storeError != null) {
            Text(
                text = storeError,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
        }
        FlowRow(
            modifier = Modifier
                .heightIn(max = 240.dp)
                .verticalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            candidates.forEach { field ->
                val checked = field in selected
                FilterChip(
                    selected = checked,
                    // At the cap only a selected chip stays interactive, so a
                    // removal is always possible and nothing else can be added.
                    enabled = !atCap || checked,
                    onClick = {
                        onPlaybookChange(
                            playbook.copy(
                                requiredFields = toggleRequiredField(selected, field, cap)
                            )
                        )
                    },
                    label = {
                        Text(
                            text = field,
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                )
            }
        }
    }
}

/**
 * The Checks editor (SRE-EDITOR-04): one card per check with its read-only id,
 * its description field and its recommended-tools chips.  Cards are appended
 * and removed only — the user-built order and every existing id stay put, so
 * the ids a saved scenario already carries keep their provenance; a fresh card
 * takes the lowest unoccupied `check-<n>` ([nextCheckId]) and starts blank,
 * and "Add check" focuses it in one motion like the list editors do.
 */
@Composable
private fun AgentScenarioChecksEditor(
    draft: AgentScenarioDraft,
    toolWhitelist: Set<String>,
    onPlaybookChange: (AgentPlaybook) -> Unit
) {
    val playbook = draft.playbook
    val maxLength = ScenarioTextRules.USER_MAX_TEXT_LENGTH
    val checks = playbook.checks
    var pendingFocusIndex by remember { mutableStateOf(-1) }
    // SRE-EDITOR-06: a save rejection naming a check's description claims the
    // focus handoff for that card; id and recommended-tools rejections only
    // scroll (the id is read-only text, the tools are chips).
    LaunchedEffect(draft.validationErrors) {
        val first = draft.validationErrors.keys.firstOrNull() ?: return@LaunchedEffect
        if (scenarioErrorListField(first) == "description") {
            val row = scenarioErrorListRow(first, "checks")
            if (row != null) pendingFocusIndex = row
        }
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        checks.forEachIndexed { index, check ->
            val descriptionFocusRequester = remember { FocusRequester() }
            LaunchedEffect(pendingFocusIndex) {
                if (pendingFocusIndex == index) {
                    // The node may not be attached yet on a fast tap; a missed
                    // focus request is cosmetic and safe to drop.
                    runCatching { descriptionFocusRequester.requestFocus() }
                    pendingFocusIndex = -1
                }
            }
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = check.id,
                            style = MaterialTheme.typography.titleSmall,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.weight(1f)
                        )
                        IconButton(
                            onClick = {
                                onPlaybookChange(
                                    playbook.copy(
                                        checks = checks.filterIndexed { position, _ ->
                                            position != index
                                        }
                                    )
                                )
                            }
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Delete,
                                contentDescription = stringResource(
                                    R.string.agent_scenario_editor_remove_check
                                )
                            )
                        }
                    }
                    // The id is editor-minted, but a stored boundary that still
                    // rejected it (store path `checks[i].id`) keeps its message
                    // while this card holds the id the store saw.
                    val idError = scenarioFieldErrorText(
                        validationErrors = draft.validationErrors,
                        path = "checks[$index].id",
                        currentValue = check.id,
                        storedValue = draft.validatedPlaybook?.checks?.getOrNull(index)?.id
                    )
                    if (idError != null) {
                        Text(
                            text = idError,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                    val errorText = scenarioFieldErrorText(
                        validationErrors = draft.validationErrors,
                        path = "checks[$index].description",
                        currentValue = check.description,
                        storedValue =
                        draft.validatedPlaybook?.checks?.getOrNull(index)?.description
                    ) ?: agentScenarioCheckDescriptionError(check.description, maxLength)?.let {
                        agentScenarioValidationErrorText(it, maxLength)
                    }
                    OutlinedTextField(
                        value = check.description,
                        onValueChange = { updated ->
                            onPlaybookChange(
                                playbook.copy(
                                    checks = checks.mapIndexed { position, existing ->
                                        if (position == index) {
                                            existing.copy(description = updated)
                                        } else {
                                            existing
                                        }
                                    }
                                )
                            )
                        },
                        label = {
                            Text(stringResource(R.string.agent_scenario_editor_check_description_label))
                        },
                        placeholder = {
                            Text(stringResource(R.string.agent_scenario_editor_check_description_hint))
                        },
                        isError = errorText != null,
                        supportingText = {
                            if (errorText != null) {
                                Text(
                                    text = errorText,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error
                                )
                            } else {
                                Text(
                                    text = stringResource(
                                        R.string.agent_scenario_editor_text_counter,
                                        check.description.length,
                                        maxLength
                                    ),
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .focusRequester(descriptionFocusRequester)
                    )
                    AgentScenarioRecommendedToolsEditor(
                        draft = draft,
                        path = "checks[$index].recommendedTools",
                        storedValue = draft.validatedPlaybook?.checks
                            ?.getOrNull(index)?.recommendedTools,
                        toolWhitelist = toolWhitelist,
                        selected = check.recommendedTools,
                        onToggle = { tool ->
                            onPlaybookChange(
                                playbook.copy(
                                    checks = checks.mapIndexed { position, existing ->
                                        if (position == index) {
                                            existing.copy(
                                                recommendedTools =
                                                toggleRecommendedTool(existing.recommendedTools, tool)
                                            )
                                        } else {
                                            existing
                                        }
                                    }
                                )
                            )
                        }
                    )
                }
            }
        }
        TextButton(
            onClick = {
                onPlaybookChange(playbook.copy(checks = appendCheck(checks)))
                pendingFocusIndex = checks.size
            }
        ) {
            Icon(Icons.Filled.Add, contentDescription = null)
            Spacer(Modifier.width(6.dp))
            Text(stringResource(R.string.agent_scenario_editor_add_check))
        }
    }
}

/**
 * The Success path editor (SRE-EDITOR-04): the same row pattern as the Intent
 * hints editor — one field per step, appended and removed in place so the
 * order the user built is never reshuffled, a fresh row focused on add.  A
 * step carries the shared text budget and the declarative rule; blank stays
 * allowed because the store accepts it too.
 */
@Composable
private fun AgentScenarioSuccessPathEditor(
    draft: AgentScenarioDraft,
    onPlaybookChange: (AgentPlaybook) -> Unit
) {
    val playbook = draft.playbook
    val maxLength = ScenarioTextRules.USER_MAX_TEXT_LENGTH
    val steps = playbook.successPath
    var pendingFocusIndex by remember { mutableStateOf(-1) }
    // SRE-EDITOR-06: a save rejection naming one of these steps claims the
    // focus handoff for that row.
    LaunchedEffect(draft.validationErrors) {
        val row = draft.validationErrors.keys.firstOrNull()
            ?.let { scenarioErrorListRow(it, "successPath") }
        if (row != null) pendingFocusIndex = row
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        steps.forEachIndexed { index, step ->
            val rowFocusRequester = remember { FocusRequester() }
            LaunchedEffect(pendingFocusIndex) {
                if (pendingFocusIndex == index) {
                    // The node may not be attached yet on a fast tap; a missed
                    // focus request is cosmetic and safe to drop.
                    runCatching { rowFocusRequester.requestFocus() }
                    pendingFocusIndex = -1
                }
            }
            val errorText = scenarioFieldErrorText(
                validationErrors = draft.validationErrors,
                path = "successPath[$index]",
                currentValue = step,
                storedValue = draft.validatedPlaybook?.successPath?.getOrNull(index)
            ) ?: agentScenarioOptionalTextError(step, maxLength)?.let {
                agentScenarioValidationErrorText(it, maxLength)
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = step,
                    onValueChange = { updated ->
                        onPlaybookChange(
                            playbook.copy(
                                successPath = steps.mapIndexed { position, existing ->
                                    if (position == index) updated else existing
                                }
                            )
                        )
                    },
                    placeholder = {
                        Text(stringResource(R.string.agent_scenario_editor_success_step_hint))
                    },
                    isError = errorText != null,
                    singleLine = true,
                    supportingText = if (errorText != null) {
                        {
                            Text(
                                text = errorText,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    } else {
                        {
                            Text(
                                text = stringResource(
                                    R.string.agent_scenario_editor_text_counter,
                                    step.length,
                                    maxLength
                                ),
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    },
                    modifier = Modifier
                        .weight(1f)
                        .focusRequester(rowFocusRequester)
                )
                IconButton(
                    onClick = {
                        onPlaybookChange(
                            playbook.copy(
                                successPath = steps.filterIndexed { position, _ ->
                                    position != index
                                }
                            )
                        )
                    }
                ) {
                    Icon(
                        imageVector = Icons.Filled.Delete,
                        contentDescription = stringResource(
                            R.string.agent_scenario_editor_remove_success_step
                        )
                    )
                }
            }
        }
        TextButton(
            onClick = {
                onPlaybookChange(playbook.copy(successPath = steps + ""))
                pendingFocusIndex = steps.size
            }
        ) {
            Icon(Icons.Filled.Add, contentDescription = null)
            Spacer(Modifier.width(6.dp))
            Text(stringResource(R.string.agent_scenario_editor_add_success_step))
        }
    }
}

/**
 * The Failure branches editor (SRE-EDITOR-04): one card per branch with the
 * condition field, the recommended-tools chips and the limitation field.  Like
 * Checks, cards are appended and removed only and a fresh card starts blank;
 * neither field is required — the store validates both with the shared text
 * rules alone, so the editor mirrors exactly that.
 */
@Composable
private fun AgentScenarioFailureBranchesEditor(
    draft: AgentScenarioDraft,
    toolWhitelist: Set<String>,
    onPlaybookChange: (AgentPlaybook) -> Unit
) {
    val playbook = draft.playbook
    val maxLength = ScenarioTextRules.USER_MAX_TEXT_LENGTH
    val branches = playbook.failureBranches
    var pendingFocusIndex by remember { mutableStateOf(-1) }
    // The limitation field cannot share the condition handoff above: one
    // pending index per field, so a rejection claims exactly one of them.
    var pendingLimitationFocusIndex by remember { mutableStateOf(-1) }
    // SRE-EDITOR-06: a save rejection naming a branch's condition or
    // limitation claims that field's handoff; recommended-tools rejections
    // only scroll (chips).
    LaunchedEffect(draft.validationErrors) {
        val first = draft.validationErrors.keys.firstOrNull() ?: return@LaunchedEffect
        val row = scenarioErrorListRow(first, "failureBranches") ?: return@LaunchedEffect
        when (scenarioErrorListField(first)) {
            "condition" -> pendingFocusIndex = row
            "limitation" -> pendingLimitationFocusIndex = row
        }
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        branches.forEachIndexed { index, branch ->
            val conditionFocusRequester = remember { FocusRequester() }
            LaunchedEffect(pendingFocusIndex) {
                if (pendingFocusIndex == index) {
                    // The node may not be attached yet on a fast tap; a missed
                    // focus request is cosmetic and safe to drop.
                    runCatching { conditionFocusRequester.requestFocus() }
                    pendingFocusIndex = -1
                }
            }
            val limitationFocusRequester = remember { FocusRequester() }
            LaunchedEffect(pendingLimitationFocusIndex) {
                if (pendingLimitationFocusIndex == index) {
                    runCatching { limitationFocusRequester.requestFocus() }
                    pendingLimitationFocusIndex = -1
                }
            }
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = stringResource(
                                R.string.agent_scenario_editor_failure_branch_label,
                                index + 1
                            ),
                            style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.weight(1f)
                        )
                        IconButton(
                            onClick = {
                                onPlaybookChange(
                                    playbook.copy(
                                        failureBranches = branches.filterIndexed { position, _ ->
                                            position != index
                                        }
                                    )
                                )
                            }
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Delete,
                                contentDescription = stringResource(
                                    R.string.agent_scenario_editor_remove_failure_branch
                                )
                            )
                        }
                    }
                    val conditionError = scenarioFieldErrorText(
                        validationErrors = draft.validationErrors,
                        path = "failureBranches[$index].condition",
                        currentValue = branch.condition,
                        storedValue =
                        draft.validatedPlaybook?.failureBranches?.getOrNull(index)?.condition
                    ) ?: agentScenarioOptionalTextError(branch.condition, maxLength)?.let {
                        agentScenarioValidationErrorText(it, maxLength)
                    }
                    OutlinedTextField(
                        value = branch.condition,
                        onValueChange = { updated ->
                            onPlaybookChange(
                                playbook.copy(
                                    failureBranches = branches.mapIndexed { position, existing ->
                                        if (position == index) {
                                            existing.copy(condition = updated)
                                        } else {
                                            existing
                                        }
                                    }
                                )
                            )
                        },
                        label = {
                            Text(stringResource(R.string.agent_scenario_editor_condition_label))
                        },
                        placeholder = {
                            Text(stringResource(R.string.agent_scenario_editor_condition_hint))
                        },
                        isError = conditionError != null,
                        supportingText = {
                            if (conditionError != null) {
                                Text(
                                    text = conditionError,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error
                                )
                            } else {
                                Text(
                                    text = stringResource(
                                        R.string.agent_scenario_editor_text_counter,
                                        branch.condition.length,
                                        maxLength
                                    ),
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .focusRequester(conditionFocusRequester)
                    )
                    AgentScenarioRecommendedToolsEditor(
                        draft = draft,
                        path = "failureBranches[$index].recommendedTools",
                        storedValue = draft.validatedPlaybook?.failureBranches
                            ?.getOrNull(index)?.recommendedTools,
                        toolWhitelist = toolWhitelist,
                        selected = branch.recommendedTools,
                        onToggle = { tool ->
                            onPlaybookChange(
                                playbook.copy(
                                    failureBranches = branches.mapIndexed { position, existing ->
                                        if (position == index) {
                                            existing.copy(
                                                recommendedTools =
                                                toggleRecommendedTool(existing.recommendedTools, tool)
                                            )
                                        } else {
                                            existing
                                        }
                                    }
                                )
                            )
                        }
                    )
                    val limitationError = scenarioFieldErrorText(
                        validationErrors = draft.validationErrors,
                        path = "failureBranches[$index].limitation",
                        currentValue = branch.limitation,
                        storedValue =
                        draft.validatedPlaybook?.failureBranches?.getOrNull(index)?.limitation
                    ) ?: agentScenarioOptionalTextError(branch.limitation, maxLength)?.let {
                        agentScenarioValidationErrorText(it, maxLength)
                    }
                    OutlinedTextField(
                        value = branch.limitation,
                        onValueChange = { updated ->
                            onPlaybookChange(
                                playbook.copy(
                                    failureBranches = branches.mapIndexed { position, existing ->
                                        if (position == index) {
                                            existing.copy(limitation = updated)
                                        } else {
                                            existing
                                        }
                                    }
                                )
                            )
                        },
                        label = {
                            Text(stringResource(R.string.agent_scenario_editor_limitation_label))
                        },
                        placeholder = {
                            Text(stringResource(R.string.agent_scenario_editor_limitation_hint))
                        },
                        isError = limitationError != null,
                        supportingText = {
                            if (limitationError != null) {
                                Text(
                                    text = limitationError,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error
                                )
                            } else {
                                Text(
                                    text = stringResource(
                                        R.string.agent_scenario_editor_text_counter,
                                        branch.limitation.length,
                                        maxLength
                                    ),
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .focusRequester(limitationFocusRequester)
                    )
                }
            }
        }
        TextButton(
            onClick = {
                onPlaybookChange(
                    playbook.copy(
                        failureBranches = branches + AgentPlaybookFailureBranch(
                            condition = "",
                            recommendedTools = emptyList(),
                            limitation = ""
                        )
                    )
                )
                pendingFocusIndex = branches.size
            }
        ) {
            Icon(Icons.Filled.Add, contentDescription = null)
            Spacer(Modifier.width(6.dp))
            Text(stringResource(R.string.agent_scenario_editor_add_failure_branch))
        }
    }
}

/**
 * The recommended-tools picker shared by the Checks and Failure branches cards
 * (SRE-EDITOR-04): the section subtitle over the whitelist chips of the
 * Initial tools editor, scoped to one check or branch.  Like Initial tools,
 * only the store's own rejection surfaces — chips come from the whitelist, so
 * nothing unavailable can be picked — and the message shows while the list
 * still matches what the store validated.
 */
@Composable
private fun AgentScenarioRecommendedToolsEditor(
    draft: AgentScenarioDraft,
    path: String,
    storedValue: Any?,
    toolWhitelist: Set<String>,
    selected: List<String>,
    onToggle: (String) -> Unit
) {
    val storeError = scenarioFieldErrorText(
        validationErrors = draft.validationErrors,
        path = path,
        currentValue = selected,
        storedValue = storedValue
    )
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            text = stringResource(R.string.agent_scenario_editor_recommended_tools_subtitle),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        AgentScenarioToolChipGroup(
            toolWhitelist = toolWhitelist,
            selected = selected,
            onToggle = onToggle
        )
        if (storeError != null) {
            Text(
                text = storeError,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
        }
    }
}

/**
 * The whitelist tool chips shared by Initial tools (SRE-EDITOR-03) and the
 * recommended-tools pickers of Checks and Failure branches (SRE-EDITOR-04):
 * one toggleable chip per whitelisted tool in whitelist order, or the
 * empty-whitelist line when this build ships no tools.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AgentScenarioToolChipGroup(
    toolWhitelist: Set<String>,
    selected: List<String>,
    onToggle: (String) -> Unit
) {
    if (toolWhitelist.isEmpty()) {
        Text(
            text = stringResource(R.string.agent_scenario_editor_initial_tools_empty),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        return
    }
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        toolWhitelist.forEach { tool ->
            FilterChip(
                selected = tool in selected,
                onClick = { onToggle(tool) },
                label = {
                    Text(
                        text = tool,
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace
                    )
                }
            )
        }
    }
}

/**
 * Read-only mode: the playbook as stored, without empty sections.  The
 * sections' fill-in guidance is deliberately absent (OPT-COPY-01): the
 * descriptions explain how to author a field, which is noise when the mode
 * only shows content that is already stored.
 */
@Composable
private fun AgentScenarioReadOnlySections(playbook: AgentPlaybook) {
    AgentScenarioEditorSection(
        stringResource(R.string.agent_scenario_editor_section_basic_info)
    ) {
        Text(
            text = playbook.title,
            style = MaterialTheme.typography.bodyMedium
        )
    }
    if (playbook.intentHints.isNotEmpty()) {
        AgentScenarioEditorSection(
            stringResource(R.string.agent_scenario_editor_section_intent_hints)
        ) {
            ReadOnlyBulletList(playbook.intentHints)
        }
    }
    if (playbook.protocols.isNotEmpty()) {
        AgentScenarioEditorSection(
            stringResource(R.string.agent_scenario_editor_section_protocols)
        ) {
            ReadOnlyBulletList(playbook.protocols)
        }
    }
    if (playbook.initialTools.isNotEmpty()) {
        AgentScenarioEditorSection(
            stringResource(R.string.agent_scenario_editor_section_initial_tools)
        ) {
            ReadOnlyBulletList(playbook.initialTools)
        }
    }
    if (playbook.requiredFields.isNotEmpty()) {
        AgentScenarioEditorSection(
            stringResource(R.string.agent_scenario_editor_section_required_fields)
        ) {
            ReadOnlyBulletList(playbook.requiredFields)
        }
    }
    if (playbook.checks.isNotEmpty()) {
        AgentScenarioEditorSection(
            stringResource(R.string.agent_scenario_editor_section_checks)
        ) {
            playbook.checks.forEach { check ->
                Text(
                    text = check.id,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = check.description,
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    text = stringResource(
                        R.string.agent_scenario_editor_recommended_tools,
                        check.recommendedTools.joinToString()
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
    if (playbook.successPath.isNotEmpty()) {
        AgentScenarioEditorSection(
            stringResource(R.string.agent_scenario_editor_section_success_path)
        ) {
            ReadOnlyBulletList(playbook.successPath)
        }
    }
    if (playbook.failureBranches.isNotEmpty()) {
        AgentScenarioEditorSection(
            stringResource(R.string.agent_scenario_editor_section_failure_branches)
        ) {
            playbook.failureBranches.forEach { branch ->
                Text(
                    text = branch.condition,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = stringResource(
                        R.string.agent_scenario_editor_recommended_tools,
                        branch.recommendedTools.joinToString()
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = stringResource(
                        R.string.agent_scenario_editor_branch_limitation,
                        branch.limitation
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
    if (playbook.requiredLimitations.isNotEmpty()) {
        AgentScenarioEditorSection(
            stringResource(R.string.agent_scenario_editor_section_limitations)
        ) {
            ReadOnlyBulletList(playbook.requiredLimitations)
        }
    }
    if (playbook.outputSections.isNotEmpty()) {
        AgentScenarioEditorSection(
            stringResource(R.string.agent_scenario_editor_section_report_sections)
        ) {
            ReadOnlyBulletList(playbook.outputSections)
        }
    }
}

@Composable
private fun AgentScenarioEditorSection(
    title: String,
    modifier: Modifier = Modifier,
    /**
     * The section's fill-in guidance.  Only the edit-mode call sites pass it;
     * the read-only details mode leaves it null so no authoring meta text
     * shows over stored content (OPT-COPY-01).
     */
    description: String? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleSmall
        )
        if (description != null) {
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        content()
    }
}

@Composable
private fun ReadOnlyBulletList(entries: List<String>) {
    Text(
        text = entries.joinToString(separator = "\n") { "• $it" },
        style = MaterialTheme.typography.bodyMedium
    )
}

// ------------------------------------------------------- validation selectors
//
// Real-time validation selectors for the editor fields.  They are plain
// functions returning string res ids (never resolved strings) so they stay
// pure JVM and directly unit-testable; the composables above resolve them
// with stringResource and give the store's own rejection precedence — via
// the shared [scenarioFieldErrorText] lookup, which localizes the store's
// reason code (OPT-ERR-01) — while it still describes the value on screen.
// The save-rejection summary card uses the same code mapping per field and
// [scenarioErrorPathLabel] to name each path.

/**
 * The real-time title error as a res id, or `null` when the title is
 * acceptable: blank means required, over-long means too long, anything else
 * must pass the shared declarative-text rule with the title limit.
 */
internal fun agentScenarioTitleError(title: String, maxLength: Int): Int? = when {
    title.isBlank() -> R.string.agent_scenario_editor_error_title_required
    title.length > maxLength -> R.string.agent_scenario_editor_error_text_too_long
    else -> agentScenarioDeclarativeTextError(title)
}

/**
 * [agentScenarioTitleError] for one intent hint, with the hint rules: blank
 * means required and the limit is the hint budget.
 */
internal fun agentScenarioHintError(hint: String, maxLength: Int): Int? = when {
    hint.isBlank() -> R.string.agent_scenario_editor_error_hint_required
    hint.length > maxLength -> R.string.agent_scenario_editor_error_text_too_long
    else -> agentScenarioDeclarativeTextError(hint)
}

/**
 * The Intent hints section error as a res id, or `null`: the store refuses a
 * scenario without any hint, so the editor says so while the list is empty.
 */
internal fun agentScenarioIntentHintsError(hints: List<String>): Int? =
    if (hints.isEmpty()) R.string.agent_scenario_editor_error_intent_hints_required else null

/**
 * [agentScenarioTitleError] for one check description (SRE-EDITOR-04): blank
 * means required, over-long means too long, anything else must pass the shared
 * declarative-text rule with the shared text budget.
 */
internal fun agentScenarioCheckDescriptionError(description: String, maxLength: Int): Int? = when {
    description.isBlank() -> R.string.agent_scenario_editor_error_check_description_required
    description.length > maxLength -> R.string.agent_scenario_editor_error_text_too_long
    else -> agentScenarioDeclarativeTextError(description)
}

/**
 * The real-time error for an optional free-text field (SRE-EDITOR-04) —
 * success-path steps and the failure-branch condition and limitation: blank is
 * allowed because the store's text rules accept it too, over-long is rejected,
 * and anything else must pass the shared declarative-text rule.
 */
internal fun agentScenarioOptionalTextError(text: String, maxLength: Int): Int? = when {
    text.length > maxLength -> R.string.agent_scenario_editor_error_text_too_long
    else -> agentScenarioDeclarativeTextError(text)
}

// ------------------------------------------------------ multi-select toggles
//
// Pure selection toggles for the Initial tools and Required fields chips
// (SRE-EDITOR-03) and the recommended-tools chips of the Checks and Failure
// branches cards (SRE-EDITOR-04).  All keep the user-built order — adding
// appends and removing filters — so an edit never reshuffles what the scenario
// already declares, and all stay JVM-pure for direct unit testing.

/**
 * One Initial tools chip toggle: adds [tool] when absent, removes it when
 * present.  An already-selected tool is never duplicated, and removing one
 * leaves the remaining order untouched.
 */
internal fun toggleInitialTool(current: List<String>, tool: String): List<String> =
    if (tool in current) current - tool else current + tool

/**
 * One Required fields chip toggle under the store's [cap]
 * ([AgentPlaybookStore.MAX_REQUIRED_FIELDS]): adds [field] only while the list
 * is below the cap, removes it whatever the count.  At the cap the call
 * degrades to a no-op instead of growing the list, and a field already present
 * is removed rather than duplicated.
 */
internal fun toggleRequiredField(current: List<String>, field: String, cap: Int): List<String> {
    if (field in current) return current - field
    if (current.size >= cap) return current
    return current + field
}

/**
 * One recommended-tools chip toggle inside a Check or Failure branch card
 * (SRE-EDITOR-04): the same never-duplicate, order-keeping toggle the Initial
 * tools chips use, scoped to one card's list.
 */
internal fun toggleRecommendedTool(current: List<String>, tool: String): List<String> =
    if (tool in current) current - tool else current + tool

/**
 * The lowest unoccupied `check-<n>` id for a new check card.  Only ids in
 * exactly that shape claim their number — anything else (a hand-named id like
 * `health`, a non-numeric tail like `check-2x`, or a zero-padded `check-01`)
 * is another legal id and does not interfere with the numbering — and holes in
 * the taken numbers are filled, so deleting a middle card recycles its id
 * before any new number is minted.
 */
internal fun nextCheckId(existingIds: List<String>): String {
    val takenNumbers = existingIds.mapNotNullTo(mutableSetOf()) { id ->
        val number = id.removePrefix(CHECK_ID_PREFIX).toIntOrNull()
        number?.takeIf { it >= 1 && id == "$CHECK_ID_PREFIX$number" }
    }
    var candidate = 1
    while (candidate in takenNumbers) candidate++
    return "$CHECK_ID_PREFIX$candidate"
}

/**
 * The check list after one "Add check": a blank card appended at the end with
 * the id [nextCheckId] mints.  The cards already there — ids, text, tools,
 * order — are returned untouched, so a saved scenario's ids keep their
 * provenance however many cards the user adds or removes afterwards.
 */
internal fun appendCheck(existing: List<AgentPlaybookCheck>): List<AgentPlaybookCheck> =
    existing + AgentPlaybookCheck(
        id = nextCheckId(existing.map { check -> check.id }),
        description = "",
        recommendedTools = emptyList()
    )

/**
 * The forbidden-content check of [ScenarioTextRules.requireDeclarativeText]
 * alone.  Length was already checked by the caller, so the shared rule runs
 * with an unbounded limit: the editor and the store boundary cannot drift
 * apart on what counts as executable-looking text.
 */
private fun agentScenarioDeclarativeTextError(text: String): Int? =
    if (runCatching {
            ScenarioTextRules.requireDeclarativeText(text, Int.MAX_VALUE)
        }.isSuccess
    ) {
        null
    } else {
        R.string.agent_scenario_editor_error_text_not_declarative
    }

/**
 * The unified field-error lookup every section shares (SRE-EDITOR-05): the
 * store's [ScenarioValidationError] (reason code + args, OPT-ERR-01) for
 * [path], but only while the field still holds exactly the value the store
 * validated ([storedValue]).  Once the user edits the value, the error
 * describes content that is no longer on screen — and for indexed paths a
 * removed row would otherwise hand its error to the row that took its place —
 * so the real-time check takes over until the next save.  Pure JVM like the
 * other selectors; [scenarioFieldErrorText] is the composable lookup the
 * sections actually call, localizing the code via
 * [agentScenarioValidationErrorMessage].
 */
internal fun scenarioFieldError(
    validationErrors: Map<String, ScenarioValidationError>,
    path: String,
    currentValue: Any?,
    storedValue: Any?
): ScenarioValidationError? {
    if (storedValue == null || storedValue != currentValue) return null
    return validationErrors[path]
}

/**
 * [scenarioFieldError] resolved to display text: the localized message for
 * the store's reason code (unmapped codes show the code itself — debuggable,
 * never blank, never a crash), or `null` when no store error stands on the
 * path for the value currently on screen.
 */
@Composable
internal fun scenarioFieldErrorText(
    validationErrors: Map<String, ScenarioValidationError>,
    path: String,
    currentValue: Any?,
    storedValue: Any?
): String? = scenarioFieldError(
    validationErrors = validationErrors,
    path = path,
    currentValue = currentValue,
    storedValue = storedValue
)?.let { agentScenarioValidationErrorMessage(it) }

/**
 * The user-facing pieces behind one summary-bar path label: the string res id
 * plus the arguments (the 1-based element indexes) it needs.  A data class so
 * the mapping stays JVM-pure and unit-testable; the composable layer resolves
 * it with [stringResource].
 */
internal data class ScenarioErrorPathLabel(val resId: Int, val args: List<Any> = emptyList())

/** The paths that name a whole field, mapped to the labels the editor uses. */
private val agentScenarioWholePathLabels = mapOf(
    "id" to R.string.agent_scenario_editor_error_path_scenario_id,
    "title" to R.string.agent_scenario_editor_error_path_title,
    "intentHints" to R.string.agent_scenario_editor_section_intent_hints,
    "protocols" to R.string.agent_scenario_editor_section_protocols,
    "initialTools" to R.string.agent_scenario_editor_section_initial_tools,
    "requiredFields" to R.string.agent_scenario_editor_section_required_fields,
    "checks" to R.string.agent_scenario_editor_section_checks,
    "successPath" to R.string.agent_scenario_editor_section_success_path,
    "failureBranches" to R.string.agent_scenario_editor_section_failure_branches,
    "requiredLimitations" to R.string.agent_scenario_editor_section_limitations,
    "outputSections" to R.string.agent_scenario_editor_section_report_sections
)

/** One indexed store path: `list[index]` or `list[index].field`. */
private val agentScenarioIndexedPathRegex =
    Regex("^([a-zA-Z]+)\\[(\\d+)\\](?:\\.([a-zA-Z]+))?$")

/**
 * The user-facing label for one store error path, or `null` when the path is
 * not recognized — the summary card then shows the raw path so a future store
 * path can never render as an empty line.  Element indexes turn 1-based
 * (`checks[2].description` reads as "Check 3 description") to match how the
 * editor numbers cards and rows.
 */
internal fun scenarioErrorPathLabel(path: String): ScenarioErrorPathLabel? {
    agentScenarioWholePathLabels[path]?.let { return ScenarioErrorPathLabel(it) }
    val match = agentScenarioIndexedPathRegex.matchEntire(path) ?: return null
    val index = match.groupValues[2].toIntOrNull()?.plus(1) ?: return null
    val field = match.groupValues[3]
    val indexed = { resId: Int -> ScenarioErrorPathLabel(resId, listOf(index)) }
    return when (match.groupValues[1]) {
        "intentHints" -> indexed(R.string.agent_scenario_editor_error_path_intent_hint)
        "protocols" -> indexed(R.string.agent_scenario_editor_error_path_protocol)
        "successPath" -> indexed(R.string.agent_scenario_editor_error_path_step)
        "requiredLimitations" -> indexed(R.string.agent_scenario_editor_error_path_limitation)
        "outputSections" -> indexed(R.string.agent_scenario_editor_error_path_report_section)
        "checks" -> when (field) {
            "" -> indexed(R.string.agent_scenario_editor_error_path_check)
            "id" -> indexed(R.string.agent_scenario_editor_error_path_check_id)
            "description" -> indexed(R.string.agent_scenario_editor_error_path_check_description)
            "recommendedTools" ->
                indexed(R.string.agent_scenario_editor_error_path_check_recommended_tools)
            else -> null
        }
        "failureBranches" -> when (field) {
            "" -> ScenarioErrorPathLabel(
                R.string.agent_scenario_editor_failure_branch_label,
                listOf(index)
            )
            "condition" -> indexed(R.string.agent_scenario_editor_error_path_branch_condition)
            "limitation" -> indexed(R.string.agent_scenario_editor_error_path_branch_limitation)
            "recommendedTools" ->
                indexed(R.string.agent_scenario_editor_error_path_branch_recommended_tools)
            else -> null
        }
        else -> null
    }
}

// ----------------------------------------------- SRE-EDITOR-06 error locating
//
// The rejected-save path → section mapping the scroll-to-first-error logic
// uses.  Pure JVM functions so the mapping is directly unit-testable, like
// [scenarioErrorPathLabel] above.

/**
 * The editor sections the scroll-to-first-error logic can bring into view.
 * [Summary] is the top of the content, where the save-rejection summary card
 * sits; it is also the anchor for header-level paths (`id`) and any path the
 * mapping does not recognize.
 */
internal enum class ScenarioEditorSection {
    Summary,
    BasicInfo,
    IntentHints,
    InitialTools,
    RequiredFields,
    Checks,
    SuccessPath,
    FailureBranches,
    Protocols,
    Limitations,
    OutputSections
}

/** Whole-field store paths and list names, mapped to their editor sections. */
private val agentScenarioSectionPaths = mapOf(
    "title" to ScenarioEditorSection.BasicInfo,
    "intentHints" to ScenarioEditorSection.IntentHints,
    "protocols" to ScenarioEditorSection.Protocols,
    "initialTools" to ScenarioEditorSection.InitialTools,
    "requiredFields" to ScenarioEditorSection.RequiredFields,
    "checks" to ScenarioEditorSection.Checks,
    "successPath" to ScenarioEditorSection.SuccessPath,
    "failureBranches" to ScenarioEditorSection.FailureBranches,
    "requiredLimitations" to ScenarioEditorSection.Limitations,
    "outputSections" to ScenarioEditorSection.OutputSections
)

/**
 * The section a store error path belongs to: `title` maps to Basic info,
 * `intentHints[1]` to Intent hints, `checks[0].description` to Checks, and so
 * on.  The header-level `id` path and every unrecognized path resolve to
 * [ScenarioEditorSection.Summary] — the top summary card — so an unknown
 * future path still lands somewhere useful instead of nowhere.
 */
internal fun scenarioErrorSection(path: String): ScenarioEditorSection {
    agentScenarioSectionPaths[path]?.let { return it }
    val match = agentScenarioIndexedPathRegex.matchEntire(path)
        ?: return ScenarioEditorSection.Summary
    return agentScenarioSectionPaths[match.groupValues[1]]
        ?: ScenarioEditorSection.Summary
}

/**
 * The 0-based row index a store path points at within the list named
 * [listName], or `null` when the path names another list, a whole-list
 * rejection, or an unknown shape.  `intentHints[1]` and a hypothetical
 * `checks[1]` both resolve through the element index; `checks[1].description`
 * resolves to the same row as the card it belongs to.
 */
internal fun scenarioErrorListRow(path: String, listName: String): Int? {
    val match = agentScenarioIndexedPathRegex.matchEntire(path) ?: return null
    if (match.groupValues[1] != listName) return null
    return match.groupValues[2].toIntOrNull()
}

/**
 * The `list[index].field` sub-field of a store path — `description`,
 * `condition`, … — or the empty string when the path names a whole element
 * (`list[index]`), a whole list, or is not a recognized indexed path.
 */
internal fun scenarioErrorListField(path: String): String {
    val match = agentScenarioIndexedPathRegex.matchEntire(path) ?: return ""
    return match.groupValues[3]
}

/**
 * Resolves one validation res id.  The too-long variants carry the field's
 * limit as %1$d; the other messages are plain sentences.
 */
@Composable
private fun agentScenarioValidationErrorText(errorRes: Int, maxLength: Int): String =
    when (errorRes) {
        R.string.agent_scenario_editor_error_text_too_long -> stringResource(errorRes, maxLength)
        else -> stringResource(errorRes)
    }

/**
 * The source-id remainder behind a `user-<rest>-copy` id, or `null` when the
 * id is not a copy id.  Mirrors the copy-id shape
 * [com.example.layanalyzer.ai.playbook.UserScenarioPlaybookStore.generateCopyId]
 * mints; a slug can collide with the shape, and accepting that residual
 * ambiguity is cheaper than reading the user layer from the UI.
 *
 * Plain JVM function (internal for [com.example.layanalyzer.ui.components.AgentScenarioCopySourceTest]
 * to pin the shape directly, like [scenarioCopySourceLabel] above); visibility
 * only — the resolution behavior is unchanged.
 */
internal fun copySourceRemainder(id: String): String? {
    if (!id.startsWith(UserScenarioStore.USER_ID_PREFIX) || !id.endsWith(COPY_ID_SUFFIX)) {
        return null
    }
    val remainder = id
        .removePrefix(UserScenarioStore.USER_ID_PREFIX)
        .removeSuffix(COPY_ID_SUFFIX)
    return remainder.takeIf { it.isNotEmpty() }
}

/**
 * The display label for the scenario a copy was made from (OPT-COPY-01):
 * the [copySourceRemainder] of [id] resolved against the host's merged
 * [playbooks] list by id, falling back to that raw remainder when no entry
 * carries it any more — the source may have been deleted, or be a built-in
 * id a package switch retired.  `null` when [id] is not a copy id, i.e. the
 * scenario was never created by copying.
 *
 * [com.example.layanalyzer.ai.playbook.UserScenarioPlaybookStore.generateCopyId]
 * mints `user-<rest>-copy` from either a built-in `<rest>` or a user
 * `user-<rest>` source, so both id shapes are probed for `<rest>`, built-in
 * first.  When both layers happen to hold the same `<rest>` the id shape
 * alone cannot say which was the source; preferring the built-in entry keeps
 * that residual ambiguity display-only, same trade as [copySourceRemainder].
 */
internal fun scenarioCopySourceLabel(
    id: String,
    playbooks: List<AgentPlaybook>
): String? {
    val remainder = copySourceRemainder(id) ?: return null
    return playbooks.firstOrNull { it.id == remainder }?.title
        ?: playbooks.firstOrNull { it.id == UserScenarioStore.USER_ID_PREFIX + remainder }?.title
        ?: remainder
}
