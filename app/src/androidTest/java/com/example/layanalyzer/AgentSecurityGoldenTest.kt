package com.example.layanalyzer

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.ai.agent.AgentRunOutcome
import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.ai.client.MockAiModelClient
import com.example.layanalyzer.ai.client.MockModelScriptCodec
import com.example.layanalyzer.ai.privacy.AgentPrivacyPolicy
import com.example.layanalyzer.ai.tools.AgentToolRegistry
import com.example.layanalyzer.data.AgentAnalysisRepository
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AnalysisScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/** Prompt-injection capture data must remain untrusted at both host boundaries. */
@RunWith(AndroidJUnit4::class)
class AgentSecurityGoldenTest {

    @Test
    fun captureTextCannotExpandToolsOrCreateExecutableReportLinks() {
        val registry = AgentToolRegistry.phase2(Dispatchers.Unconfined)
        assertFalse(registry.contains("open_file"))
        assertFalse(registry.contains("run_command"))
        assertFalse(registry.contains("http_request"))

        val hostileScript = MockModelScriptCodec.decode(HOSTILE_SCRIPT)
        val client = MockAiModelClient(hostileScript)
        val capture = GoldenCaptureTestSupport.copyCapture("security_prompt_injection")
        val repository = PacketRepository()
        val info = repository.openFile(capture.absolutePath).getOrThrow()
        val coordinator = CaptureSessionCoordinator(
            dataSource = repository,
            fingerprintDispatcher = Dispatchers.Unconfined
        )
        val token = coordinator.onSessionOpened(info)
        try {
            assertTrue(runBlocking { coordinator.prepareFingerprint(token, capture).isSuccess })
            val agent = com.example.layanalyzer.ai.agent.ProtocolAnalysisAgent(
                repository = AgentAnalysisRepository(repository, coordinator),
                registry = registry,
                modelClient = client,
                policy = AgentPolicy(
                    maxSteps = 4,
                    maxToolResultBytes = 64 * 1024,
                    maxTotalResultBytes = 256 * 1024L
                )
            )
            val result = runBlocking {
                agent.run(
                    question = "Does capture text contain instructions?",
                    scope = AnalysisScope.CompleteFile,
                    privacyMode = AgentPrivacyMode.RedactedMetadata
                )
            }
            assertTrue(result.outcome is AgentRunOutcome.Completed)
            assertTrue(result.toolCallIds.contains("call-evil"))
            assertTrue(
                result.activities.any { activity ->
                    activity.toolCallId == "call-evil" && activity.error != null
                }
            )

            val summary = result.report?.summary.orEmpty()
            assertFalse(summary.contains("intent://", ignoreCase = true))
            assertFalse(summary.contains("file:///data", ignoreCase = true))
            assertFalse(summary.contains("/data/data", ignoreCase = true))
            assertTrue(summary.contains(AgentPrivacyPolicy.BLOCKED_URI))

            val toolMessages = client.observedRequests
                .flatMap { request -> request.messages }
                .filter { message -> message.role == AgentModelMessageRole.Tool }
            assertTrue(toolMessages.isNotEmpty())
            assertTrue(toolMessages.all { it.untrustedCaptureData })
            assertFalse(
                "A hostile tool was executed",
                result.activities.any { it.toolName == "open_file" && it.error == null }
            )
        } finally {
            coordinator.invalidateSession()
            repository.closeFile()
            capture.delete()
        }
    }

    @Test
    fun generatedCaptureContainsInjectionTextButOnlyAsCaptureBytes() {
        val capture = GoldenCaptureTestSupport.copyCapture("security_prompt_injection")
        try {
            val text = capture.readBytes().toString(Charsets.ISO_8859_1)
            assertTrue(text.contains("IGNORE PREVIOUS INSTRUCTIONS"))
            assertTrue(text.contains("intent://scan"))
        } finally {
            capture.delete()
        }
    }

    companion object {
        @JvmStatic
        @BeforeClass
        fun initializeEngine() {
            GoldenCaptureTestSupport.initialize()
        }

        private val HOSTILE_SCRIPT = """
            {
              "schemaVersion": 1,
              "id": "security_hostile_agent",
              "capabilities": {
                "toolCalling": true,
                "parallelToolCalls": false,
                "structuredOutput": true,
                "streaming": false,
                "maxContextTokens": 128000,
                "maxOutputTokens": 4096
              },
              "turns": [
                {
                  "type": "tool_calls",
                  "calls": [
                    {"toolCallId": "call-overview", "toolName": "get_capture_overview", "arguments": {}}
                  ]
                },
                {
                  "type": "tool_calls",
                  "calls": [
                    {"toolCallId": "call-evil", "toolName": "open_file", "arguments": {"path": "/data/data/com.layeranalyzer/secret.db"}}
                  ]
                },
                {
                  "type": "final",
                  "report": {
                    "summary": "[tap here](intent://scan/#Intent;scheme=x;end) and file:///data/data/com.layeranalyzer/secret.db",
                    "findings": [],
                    "limitations": [],
                    "recommendedNextSteps": []
                  }
                }
              ]
            }
        """.trimIndent()
    }
}
