package com.example.layanalyzer.ui.components

import android.content.res.Configuration
import androidx.compose.runtime.Composable
import androidx.compose.ui.tooling.preview.Preview
import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentConversationRole
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import com.example.layanalyzer.model.AgentRunPhase
import com.example.layanalyzer.model.AgentToolActivity
import com.example.layanalyzer.model.AgentToolActivityStatus
import com.example.layanalyzer.model.DisplayFilterUiState
import com.example.layanalyzer.model.FileSessionInfo
import com.example.layanalyzer.model.ProtocolAgentUiState
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme

/**
 * Previews for the Agent page.
 *
 * These cover the states AI-08 §9 calls out, including the ones that are awkward
 * to reach by hand — a partial report, a failure, a cancelled run — so the
 * "stopped early" and error treatments can be checked without driving a session.
 * The dark variants exist because severity and evidence colours are the part
 * most likely to lose contrast.
 */
private val previewFile = FileSessionInfo(
    displayName = "ims-registration.pcap",
    sizeBytes = 4_312_064L,
    fileType = "pcapng",
    frameCount = 18_402,
    localPath = "/data/captures/ims-registration.pcapng"
)

private val previewFinding = AgentFinding(
    id = "finding-1",
    title = "REGISTER was never retried after the 401 challenge",
    severity = AgentFindingSeverity.Error,
    confidence = AgentConfidence.High,
    conclusion = "The UE received 401 Unauthorized in frame 42 but sent no second " +
        "REGISTER carrying the Authorization header, so registration never completed.",
    evidence = listOf(
        AgentEvidence(
            type = AgentEvidenceType.Frame,
            frameNumber = 42L,
            observation = "401 Unauthorized",
            sourceToolCallId = "call-1"
        ),
        AgentEvidence(
            type = AgentEvidenceType.DisplayFilter,
            displayFilter = "sip.Method == \"REGISTER\"",
            observation = "1 registration attempt",
            sourceToolCallId = "call-1"
        )
    ),
    alternatives = listOf("The retry may have been sent on an interface this capture does not cover."),
    recommendations = listOf("Confirm the IMS credentials provisioned on the UE.")
)

private val previewReport = AgentReport(
    summary = "IMS registration did not complete: the challenge was never answered.",
    findings = listOf(previewFinding),
    recommendedNextSteps = listOf("Capture again with the SIP signalling interface included."),
    completeness = AgentReportCompleteness.Complete
)

private val previewActivities = listOf(
    AgentToolActivity(
        toolCallId = "call-1",
        toolName = "get_capture_overview",
        status = AgentToolActivityStatus.Succeeded,
        argumentsSummary = "scope",
        startedAtMillis = 1_000L,
        completedAtMillis = 1_180L,
        returnedCount = 1,
        totalCount = 1
    ),
    AgentToolActivity(
        toolCallId = "call-2",
        toolName = "get_expert_info",
        status = AgentToolActivityStatus.Succeeded,
        argumentsSummary = "displayFilter, severity",
        startedAtMillis = 1_200L,
        completedAtMillis = 1_920L,
        returnedCount = 50,
        totalCount = 214,
        truncated = true
    )
)

@Composable
private fun PreviewAgentScreen(state: ProtocolAgentUiState) {
    LayerAnalyzerTheme {
        ProtocolAgentScreen(
            uiState = state,
            currentFile = previewFile,
            displayFilter = DisplayFilterUiState(
                appliedExpression = "sip",
                visibleCount = 312,
                totalCount = 18_402
            ),
            onSubmitQuestion = { _, _, _, _ -> },
            onContinueConversation = {},
            onCancel = {},
            onRetry = {},
            onNewConversation = {},
            onClearTransientError = {},
            onFrameClick = {}
        )
    }
}

@Preview(name = "Agent · no capture", showBackground = true)
@Composable
private fun ProtocolAgentScreenNoCapturePreview() {
    LayerAnalyzerTheme {
        ProtocolAgentScreen(
            uiState = ProtocolAgentUiState(),
            currentFile = null,
            displayFilter = DisplayFilterUiState(),
            onSubmitQuestion = { _, _, _, _ -> },
            onContinueConversation = {},
            onCancel = {},
            onRetry = {},
            onNewConversation = {},
            onClearTransientError = {},
            onFrameClick = {}
        )
    }
}

@Preview(name = "Agent · idle", showBackground = true, heightDp = 780)
@Composable
private fun ProtocolAgentScreenIdlePreview() {
    PreviewAgentScreen(ProtocolAgentUiState())
}

@Preview(name = "Agent · running", showBackground = true, heightDp = 780)
@Composable
private fun ProtocolAgentScreenRunningPreview() {
    PreviewAgentScreen(
        ProtocolAgentUiState(
            phase = AgentRunPhase.RunningTool,
            messages = listOf(
                AgentConversationItem(
                    id = "m1",
                    role = AgentConversationRole.User,
                    content = "Why did IMS registration fail?"
                )
            ),
            activeTool = previewActivities[1].copy(
                status = AgentToolActivityStatus.Running,
                completedAtMillis = null
            ),
            toolActivities = listOf(
                previewActivities[0],
                previewActivities[1].copy(
                    status = AgentToolActivityStatus.Running,
                    completedAtMillis = null
                )
            ),
            completedSteps = 1
        )
    )
}

@Preview(name = "Agent · completed", showBackground = true, heightDp = 900)
@Composable
private fun ProtocolAgentScreenCompletedPreview() {
    PreviewAgentScreen(
        ProtocolAgentUiState(
            phase = AgentRunPhase.Completed,
            messages = listOf(
                AgentConversationItem(
                    id = "m1",
                    role = AgentConversationRole.User,
                    content = "Why did IMS registration fail?"
                ),
                AgentConversationItem(
                    id = "m2",
                    role = AgentConversationRole.Tool,
                    content = "214 expert items, 50 returned",
                    toolName = "get_expert_info",
                    untrustedCaptureData = true
                )
            ),
            toolActivities = previewActivities,
            completedSteps = 2,
            report = previewReport
        )
    )
}

@Preview(
    name = "Agent · completed (dark)",
    showBackground = true,
    heightDp = 900,
    uiMode = Configuration.UI_MODE_NIGHT_YES
)
@Composable
private fun ProtocolAgentScreenCompletedDarkPreview() {
    ProtocolAgentScreenCompletedPreview()
}

@Preview(name = "Agent · partial report", showBackground = true, heightDp = 900)
@Composable
private fun ProtocolAgentScreenPartialPreview() {
    PreviewAgentScreen(
        ProtocolAgentUiState(
            phase = AgentRunPhase.Completed,
            toolActivities = previewActivities,
            completedSteps = 2,
            report = previewReport.copy(
                completeness = AgentReportCompleteness.Partial,
                limitations = listOf(
                    "Expert info was truncated to 50 of 214 items.",
                    "The analysis stopped at the step budget before checking media."
                )
            )
        )
    )
}

@Preview(
    name = "Agent · partial report (dark)",
    showBackground = true,
    heightDp = 900,
    uiMode = Configuration.UI_MODE_NIGHT_YES
)
@Composable
private fun ProtocolAgentScreenPartialDarkPreview() {
    ProtocolAgentScreenPartialPreview()
}

@Preview(name = "Agent · failed", showBackground = true, heightDp = 780)
@Composable
private fun ProtocolAgentScreenFailedPreview() {
    PreviewAgentScreen(
        ProtocolAgentUiState(
            phase = AgentRunPhase.Failed,
            toolActivities = listOf(
                previewActivities[0],
                previewActivities[1].copy(
                    status = AgentToolActivityStatus.Failed,
                    error = AgentError(
                        code = AgentErrorCode.TOOL_TIMEOUT,
                        userMessage = "The step did not finish in time."
                    )
                )
            ),
            completedSteps = 2,
            error = AgentError(
                code = AgentErrorCode.MAX_STEPS_REACHED,
                userMessage = "The analysis stopped after 12 steps.",
                retryable = true
            )
        )
    )
}

@Preview(name = "Agent · cancelled", showBackground = true, heightDp = 780)
@Composable
private fun ProtocolAgentScreenCancelledPreview() {
    PreviewAgentScreen(
        ProtocolAgentUiState(
            phase = AgentRunPhase.Cancelled,
            toolActivities = listOf(previewActivities[0]),
            completedSteps = 1
        )
    )
}

/** Large-font check: the composer must not collide with the send control. */
@Preview(name = "Agent · idle, large font", showBackground = true, heightDp = 780, fontScale = 1.8f)
@Composable
private fun ProtocolAgentScreenLargeFontPreview() {
    PreviewAgentScreen(ProtocolAgentUiState())
}

@Preview(name = "Finding card", showBackground = true, widthDp = 380)
@Composable
private fun AgentFindingCardPreview() {
    LayerAnalyzerTheme {
        AgentFindingCard(finding = previewFinding, onFrameClick = {})
    }
}

@Preview(
    name = "Finding card (dark)",
    showBackground = true,
    widthDp = 380,
    uiMode = Configuration.UI_MODE_NIGHT_YES
)
@Composable
private fun AgentFindingCardDarkPreview() {
    AgentFindingCardPreview()
}

@Preview(name = "Tool activity list", showBackground = true, widthDp = 380)
@Composable
private fun AgentToolActivityListPreview() {
    LayerAnalyzerTheme {
        AgentToolActivityList(
            activities = previewActivities + AgentToolActivity(
                toolCallId = "call-3",
                toolName = "validate_display_filter",
                status = AgentToolActivityStatus.Failed,
                argumentsSummary = "expression",
                startedAtMillis = 2_000L,
                completedAtMillis = 2_040L,
                error = AgentError(
                    code = AgentErrorCode.INVALID_DISPLAY_FILTER,
                    userMessage = "The filter did not compile."
                )
            )
        )
    }
}

