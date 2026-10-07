// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.playbook.AgentPlaybook
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AnalysisWorkspace
import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.EvidenceSource
import com.example.layanalyzer.model.WorkspaceNote
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins the evidence-set section injection (EVL-CONTEXT-02): its own host
 * system message after the cacheable block and before history, the four
 * anti-bias disciplines, the byte-identical prompt when the section is
 * absent, and the untouched product-context invariant.
 */
class PromptAssemblerTest {

    private fun assembler() = PromptAssembler()

    private fun tools() = listOf(AgentToolDefinition("get_capture_overview"))

    private fun snapshot() = AgentCaptureSnapshot(frameCount = 120, displayFilter = "tcp.port == 5060")

    private fun policy() = AgentPolicy()

    private fun playbook() = AgentPlaybook.generalCaptureHealth()

    @Test
    fun promptAssemblerVersionIsBumpedToPrompt9() {
        assertEquals("prompt-9", PromptAssembler.VERSION)
    }

    /**
     * With no section the message list must equal the pre-change shape,
     * constructed here independently: cacheable system block, then the user
     * question.  Deep equality on the data classes compares every content
     * byte.
     */
    @Test
    fun absentEvidenceSetSectionLeavesMessageListByteIdentical() {
        val snapshot = snapshot()
        val policy = policy()
        val tools = tools()
        val playbook = playbook()

        val expected = listOf(
            AgentModelMessage.system(
                content = listOf(
                    PromptAssembler.SYSTEM_CONSTRAINTS,
                    PromptAssembler().productContext(snapshot, policy, AgentPrivacyMode.RedactedMetadata, tools),
                    playbook.promptSection()
                ).joinToString("\n\n"),
                cacheable = true
            ),
            AgentModelMessage.user("Analyze this capture")
        )

        val actual = assembler().initialMessages(
            question = "Analyze this capture",
            snapshot = snapshot,
            policy = policy,
            privacyMode = AgentPrivacyMode.RedactedMetadata,
            tools = tools,
            playbook = playbook
        )

        assertEquals(expected, actual)
    }

    @Test
    fun evidenceSetSectionIsOwnSystemMessageBetweenCacheableBlockAndHistory() {
        val section = assembler().buildEvidenceSetSection(
            "Evidence set summary (2 frame(s)):\nFrames: 41, 42\nItems:\n" +
                "- frame 41: source=Manual; note: none\n"
        )
        val history = listOf(
            AgentModelMessage.user("Why did registration fail?"),
            AgentModelMessage.assistant("The server returned 403."),
            AgentModelMessage.system("host replay marker that must be filtered out")
        )

        val messages = assembler().initialMessages(
            question = "Check frame 41 again",
            snapshot = snapshot(),
            policy = policy(),
            privacyMode = AgentPrivacyMode.RedactedMetadata,
            tools = tools(),
            playbook = playbook(),
            history = history,
            evidenceSetSection = section
        )

        assertEquals(AgentModelMessageRole.System, messages[0].role)
        assertEquals("ephemeral", messages[0].cacheControl?.type)
        assertFalse(section == messages[0].content)

        val sectionMessage = messages[1]
        assertEquals(AgentModelMessageRole.System, sectionMessage.role)
        assertEquals(section, sectionMessage.content)
        assertEquals(null, sectionMessage.cacheControl)

        // History follows the section; the replayed system line is dropped.
        assertEquals(AgentModelMessageRole.User, messages[2].role)
        assertEquals("Why did registration fail?", messages[2].content)
        assertTrue(messages.none { it.role == AgentModelMessageRole.System && it.content == "host replay marker that must be filtered out" })
        assertEquals(AgentModelMessageRole.User, messages.last().role)
        assertTrue(messages.last().content.startsWith("Check frame 41 again"))
    }

    @Test
    fun evidenceSetSectionPrecedesReplayedPriorContextSection() {
        val section = assembler().buildEvidenceSetSection("Evidence set summary (1 frame(s)):\nFrames: 41\nItems:\n")

        val messages = assembler().initialMessages(
            question = "Follow-up",
            snapshot = snapshot(),
            policy = policy(),
            privacyMode = AgentPrivacyMode.RedactedMetadata,
            tools = tools(),
            playbook = playbook(),
            history = listOf(AgentModelMessage.user("earlier question")),
            evidenceSetSection = section
        )

        // A replayed history suppresses priorContext, so with history present
        // the section is still the first message after the cacheable block.
        assertEquals(section, messages[1].content)
        assertEquals(AgentModelMessageRole.System, messages[1].role)
    }

    @Test
    fun evidenceSetSectionCarriesTheFourAntiBiasDisciplines() {
        val section = assembler().buildEvidenceSetSection(
            "Evidence set summary (1 frame(s)):\nFrames: 41\nItems:\n"
        )

        assertTrue(
            "discipline 1: focus set, not conclusions",
            section.contains("The flagged evidence set is a focus set, not conclusions")
        )
        assertTrue(
            "discipline 2: re-confirm by re-running approved tools in this run",
            section.contains("must be re-confirmed by re-running the approved tools in this run")
        )
        assertTrue(
            "discipline 3: no anomaly assumption from flagging",
            section.contains("Do not assume those frames are anomalous just because they were flagged")
        )
        assertTrue(
            "discipline 4: outside-frame evidence reported as usual",
            section.contains("Strong evidence on frames outside the flagged set must be reported as usual")
        )
        assertTrue(section.startsWith(PromptAssembler.HOST_EVIDENCE_SET_HEADER))
    }

    @Test
    fun sectionBuiltFromEvidenceSetSummaryBuilderTravelsIntoTheMessageList() {
        // End-to-end through the real builder: a non-empty summary must reach
        // the message list wrapped by buildEvidenceSetSection.
        val summary = "Evidence set summary (1 frame(s)):\nFrames: 7\nItems:\n" +
            "- frame 7: source=Manual; note: none\n"
        val section = assembler().buildEvidenceSetSection(summary)

        val messages = assembler().initialMessages(
            question = "Analyze",
            snapshot = snapshot(),
            policy = policy(),
            privacyMode = AgentPrivacyMode.RedactedMetadata,
            tools = tools(),
            playbook = playbook(),
            evidenceSetSection = section
        )

        assertEquals(3, messages.size)
        assertTrue(messages[1].content.contains(summary))
        assertNotEquals(messages[0].content, messages[1].content)
    }

    /**
     * A summary the builder itself had to truncate keeps its explicit
     * truncated declaration when it travels through the evidence-set
     * section into the message list — the cut is never silenced by the
     * wrapping, and the anti-bias framing stays ahead of it.
     */
    @Test
    fun truncatedEvidenceSectionTravelsIntoTheMessageListWithItsDeclaration() {
        val longNoteText = "y".repeat(200)
        val workspace = AnalysisWorkspace(
            fileFingerprint = "fp",
            displayName = "capture.pcap",
            evidenceItems = (1L..60L).map { EvidenceItem(frameNumber = it, source = EvidenceSource.Manual) },
            notes = (1L..60L).map { WorkspaceNote(frameNumber = it, text = longNoteText, updatedAtMillis = 1L) }
        )
        val summary = EvidenceSetSummaryBuilder.build(workspace) { it }!!
        assertTrue(summary.contains("[truncated:"))

        val section = assembler().buildEvidenceSetSection(summary)
        val messages = assembler().initialMessages(
            question = "Analyze",
            snapshot = snapshot(),
            policy = policy(),
            privacyMode = AgentPrivacyMode.RedactedMetadata,
            tools = tools(),
            playbook = playbook(),
            evidenceSetSection = section
        )

        assertEquals(3, messages.size)
        val sectionMessage = messages[1]
        assertTrue(sectionMessage.content.startsWith(PromptAssembler.HOST_EVIDENCE_SET_HEADER))
        assertTrue(sectionMessage.content.contains(summary))
        assertTrue(sectionMessage.content.contains("items shown]"))
    }

    /** productContext keeps its no-capture-content invariant after the bump. */
    @Test
    fun productContextStaysFreeOfCaptureContent() {
        val snapshot = AgentCaptureSnapshot(
            frameCount = 991,
            displayFilter = "SECRET-FILTER tcp.payload == \"classified\""
        )
        val context = assembler().productContext(
            snapshot = snapshot,
            policy = policy(),
            privacyMode = AgentPrivacyMode.RedactedMetadata,
            tools = tools()
        )

        assertTrue(context.contains("Product context version: prompt-9"))
        assertFalse(context.contains("991"))
        assertFalse(context.contains("SECRET-FILTER"))
        assertFalse(context.contains("classified"))
        assertFalse(context.contains(PromptAssembler.HOST_EVIDENCE_SET_HEADER))
    }
}
