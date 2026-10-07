// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentAnalysisMode
import com.example.layanalyzer.model.AgentAnalysisPlan
import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentModelInteraction
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentRunPhase
import com.example.layanalyzer.model.AgentTokenUsage
import com.example.layanalyzer.model.AgentToolActivity

/**
 * The live, in-progress trajectory of one Agent run, owned by the
 * [com.example.layanalyzer.ai.background.AgentRunCoordinator] rather than by a
 * ViewModel.  Keeping it here — as a replayable state rather than a stream of
 * one-off events — is what lets a ViewModel created after the run started
 * (rotation, a second Activity) show the same transcript instead of an empty
 * screen, and it is the in-memory source the Phase 4 checkpoint serialises.
 */
data class AgentRunSnapshot(
    val phase: AgentRunPhase = AgentRunPhase.Idle,
    val messages: List<AgentConversationItem> = emptyList(),
    val modelInteractions: List<AgentModelInteraction> = emptyList(),
    val toolActivities: List<AgentToolActivity> = emptyList(),
    val activeTool: AgentToolActivity? = null,
    val completedSteps: Int = 0,
    val streamingText: String = "",
    val analysisPlan: AgentAnalysisPlan? = null,
    val completedPlanSteps: Int = 0,
    val report: AgentReport? = null,
    val error: AgentError? = null,
    val completionWarning: AgentError? = null,
    val analysisMode: AgentAnalysisMode = AgentAnalysisMode.FullAgent,
    val tokenUsage: AgentTokenUsage? = null,
    /**
     * The finished run's replayable model messages, set only on a terminal
     * outcome that committed its trajectory (completed or partial report).
     * Empty while running and after a cancellation.
     */
    val transcript: List<AgentModelMessage> = emptyList()
)
