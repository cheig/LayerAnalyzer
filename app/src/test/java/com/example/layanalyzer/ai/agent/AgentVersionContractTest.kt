package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentPrivacyMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins the published version strings (OPT-ARCH-03) so a silent bump or typo
 * in the constants cannot slip through: these values are recorded in report
 * provenance and in the assembled prompt surface.
 */
class AgentVersionContractTest {
    @Test
    fun promptAssemblerVersionIsPinned() {
        assertEquals("prompt-9", PromptAssembler.VERSION)
    }

    @Test
    fun agentPromptVersionIsPinned() {
        assertEquals("phase2-1", AgentPrompt.VERSION)
    }

    @Test
    fun agentVersionIsPinned() {
        assertEquals("ai-16", AgentPrompt.AGENT_VERSION)
    }

    @Test
    fun outputSchemaVersionIsPinned() {
        assertEquals("agent-report-2", AgentPrompt.OUTPUT_SCHEMA_VERSION)
    }

    @Test
    fun productContextCarriesPinnedVersionStrings() {
        val context = PromptAssembler().productContext(
            snapshot = AgentCaptureSnapshot(frameCount = 991),
            policy = AgentPolicy(),
            privacyMode = AgentPrivacyMode.RedactedMetadata,
            tools = emptyList()
        )

        assertTrue(
            "product context must state the prompt version line",
            context.contains("Product context version: prompt-9")
        )
        assertTrue(
            "product context must state the output schema version",
            context.contains("Output schema: agent-report-2")
        )
    }
}
