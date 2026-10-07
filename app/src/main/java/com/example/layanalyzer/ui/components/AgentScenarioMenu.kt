package com.example.layanalyzer.ui.components

import com.example.layanalyzer.ai.playbook.ScenarioOrigin

/**
 * Actions the scenario chip long-press menu can offer for one playbook.
 *
 * The list is origin-driven ([agentScenarioMenuActions]); the UI renders one
 * menu entry per action in the returned order.
 */
enum class AgentScenarioMenuAction {
    Edit,
    ViewDetails,
    CopyAsDuplicate,
    Delete
}

/**
 * Menu actions for a scenario chip, in the order they are shown.
 *
 * The preset lock is structural: built-in scenarios (shipped in assets or a
 * verified downloaded package) can only be duplicated or inspected, never
 * edited or deleted — [com.example.layanalyzer.viewmodel.ProtocolAgentViewModel]
 * rejects such calls, so the menu never offers the affordance in the first
 * place. User scenarios own the full set.
 */
fun agentScenarioMenuActions(origin: ScenarioOrigin): List<AgentScenarioMenuAction> = when (origin) {
    ScenarioOrigin.BuiltIn -> listOf(
        AgentScenarioMenuAction.CopyAsDuplicate,
        AgentScenarioMenuAction.ViewDetails
    )
    ScenarioOrigin.User -> listOf(
        AgentScenarioMenuAction.Edit,
        AgentScenarioMenuAction.CopyAsDuplicate,
        AgentScenarioMenuAction.Delete
    )
}
