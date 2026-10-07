// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.playbook

import com.example.layanalyzer.ai.tools.DeclareAnalysisPlanTool
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pins the SRE-ARCH-03 contract for [PlaybookParsing]: the reusable validation
 * entry point applies exactly the rules package decoding applies — exact keys,
 * id/version rules, tool whitelist, field table, the 32-field cap and
 * non-empty initial tools — so user scenario saves go through the same
 * boundary instead of a weaker copy of it.
 */
class PlaybookParsingTest {

    @Test
    fun validPlaybookParses() {
        val playbook = PlaybookParsing.parsePlaybook(validPlaybook(), availableTools, "playbooks[0]")

        assertEquals("general-capture-health", playbook.id)
        assertEquals(1, playbook.version)
        assertEquals(listOf("get_capture_overview"), playbook.initialTools)
        assertEquals(listOf("get_statistics"), playbook.checks.single().recommendedTools)
    }

    @Test
    fun unknownInitialToolIsRejectedWithCallerContext() {
        val playbook = validPlaybook().put("initialTools", listOf("sip.unavailable-tool"))

        val failure = runCatching {
            PlaybookParsing.parsePlaybook(playbook, availableTools, "playbooks[7]")
        }

        val rejection = failure.exceptionOrNull() as PlaybookValidationException
        assertEquals(
            "playbooks[7].initialTools references unavailable tools: sip.unavailable-tool",
            rejection.message
        )
        // OPT-ERR-01: the same rejection carries a structured code + path.
        assertEquals(ScenarioValidationCodes.TOOL_NOT_ALLOWED, rejection.code)
        assertEquals("playbooks[7].initialTools", rejection.path)
        assertEquals(mapOf("tool" to "sip.unavailable-tool"), rejection.args)
    }

    @Test
    fun unknownCheckToolIsRejected() {
        val playbook = validPlaybook().put(
            "checks",
            listOf(
                mapOf(
                    "id" to "health",
                    "description" to "Read the overview",
                    "recommendedTools" to listOf("sip.unavailable-tool")
                )
            )
        )

        val failure = runCatching {
            PlaybookParsing.parsePlaybook(playbook, availableTools, "playbooks[0]")
        }

        val rejection = failure.exceptionOrNull() as PlaybookValidationException
        assertEquals(
            "playbooks[0].checks[0].recommendedTools references unavailable tools: sip.unavailable-tool",
            rejection.message
        )
        assertEquals(ScenarioValidationCodes.TOOL_NOT_ALLOWED, rejection.code)
        assertEquals("playbooks[0].checks[0].recommendedTools", rejection.path)
    }

    @Test
    fun unknownFailureBranchToolIsRejected() {
        val playbook = validPlaybook().put(
            "failureBranches",
            listOf(
                mapOf(
                    "condition" to "A query fails",
                    "recommendedTools" to listOf("sip.unavailable-tool"),
                    "limitation" to "State the incomplete coverage."
                )
            )
        )

        val failure = runCatching {
            PlaybookParsing.parsePlaybook(playbook, availableTools, "playbooks[0]")
        }

        val rejection = failure.exceptionOrNull() as PlaybookValidationException
        assertEquals(
            "playbooks[0].failureBranches[0].recommendedTools references unavailable tools: sip.unavailable-tool",
            rejection.message
        )
        assertEquals(ScenarioValidationCodes.TOOL_NOT_ALLOWED, rejection.code)
        assertEquals("playbooks[0].failureBranches[0].recommendedTools", rejection.path)
    }

    @Test
    fun unsupportedRequiredFieldIsRejected() {
        val playbook = validPlaybook().put("requiredFields", listOf("sip.untrusted-field"))

        val failure = runCatching {
            PlaybookParsing.parsePlaybook(playbook, availableTools, "playbooks[0]")
        }

        val rejection = failure.exceptionOrNull() as PlaybookValidationException
        assertEquals(
            "playbooks[0].requiredFields references unsupported fields: sip.untrusted-field",
            rejection.message
        )
        assertEquals(ScenarioValidationCodes.FIELD_NOT_SUPPORTED, rejection.code)
        assertEquals("playbooks[0].requiredFields", rejection.path)
        assertEquals(mapOf("field" to "sip.untrusted-field"), rejection.args)
    }

    @Test
    fun requiredFieldsBeyondTheCapAreRejected() {
        val fields = AgentPlaybookStore.SUPPORTED_REQUIRED_FIELDS.toList().take(AgentPlaybookStore.MAX_REQUIRED_FIELDS + 1)
        val playbook = validPlaybook().put("requiredFields", fields)

        val failure = runCatching {
            PlaybookParsing.parsePlaybook(playbook, availableTools, "playbooks[0]")
        }

        val rejection = failure.exceptionOrNull() as PlaybookValidationException
        assertEquals(
            "playbooks[0].requiredFields exceeds ${AgentPlaybookStore.MAX_REQUIRED_FIELDS} fields.",
            rejection.message
        )
        assertEquals(ScenarioValidationCodes.REQUIRED_FIELDS_CAP, rejection.code)
        assertEquals(
            mapOf("max" to AgentPlaybookStore.MAX_REQUIRED_FIELDS.toString()),
            rejection.args
        )
    }

    @Test
    fun emptyInitialToolsAreRejected() {
        // availableTools deliberately lacks declare_analysis_plan, so nothing
        // is injected and the empty list survives parsing up to the check.
        val playbook = validPlaybook().put("initialTools", emptyList<String>())

        val failure = runCatching {
            PlaybookParsing.parsePlaybook(playbook, availableTools, "playbooks[0]")
        }

        val rejection = failure.exceptionOrNull() as PlaybookValidationException
        assertEquals("playbooks[0].initialTools must not be empty.", rejection.message)
        assertEquals(ScenarioValidationCodes.INITIAL_TOOLS_EMPTY, rejection.code)
        assertEquals("playbooks[0].initialTools", rejection.path)
    }

    @Test
    fun unstableIdIsRejected() {
        val playbook = validPlaybook().put("id", "General-Capture")

        val failure = runCatching {
            PlaybookParsing.parsePlaybook(playbook, availableTools, "playbooks[0]")
        }

        val rejection = failure.exceptionOrNull() as PlaybookValidationException
        assertEquals("playbooks[0].id is not a stable id.", rejection.message)
        assertEquals(ScenarioValidationCodes.ID_INVALID, rejection.code)
        assertEquals("playbooks[0].id", rejection.path)
    }

    @Test
    fun nonPositiveVersionIsRejected() {
        val playbook = validPlaybook().put("version", 0)

        val failure = runCatching {
            PlaybookParsing.parsePlaybook(playbook, availableTools, "playbooks[0]")
        }

        val rejection = failure.exceptionOrNull() as PlaybookValidationException
        assertEquals("playbooks[0].version must be positive.", rejection.message)
        assertEquals(ScenarioValidationCodes.VERSION_NOT_POSITIVE, rejection.code)
        assertEquals("playbooks[0].version", rejection.path)
    }

    @Test
    fun unknownAndMissingKeysAreRejected() {
        val unknownKey = validPlaybook().put("origin", "user")
        val missingKey = validPlaybook().also { it.remove("title") }

        runCatching { PlaybookParsing.parsePlaybook(unknownKey, availableTools, "playbooks[0]") }
            .exceptionOrNull()!!.let { failure ->
                assertEquals("playbooks[0] has unknown properties: origin", failure.message)
                val rejection = failure as PlaybookValidationException
                assertEquals(ScenarioValidationCodes.UNKNOWN_PROPERTIES, rejection.code)
                assertEquals(mapOf("properties" to "origin"), rejection.args)
            }
        runCatching { PlaybookParsing.parsePlaybook(missingKey, availableTools, "playbooks[0]") }
            .exceptionOrNull()!!.let { failure ->
                assertEquals("playbooks[0] is missing properties: title", failure.message)
                val rejection = failure as PlaybookValidationException
                assertEquals(ScenarioValidationCodes.MISSING_PROPERTIES, rejection.code)
                assertEquals(mapOf("properties" to "title"), rejection.args)
            }
    }

    @Test
    fun declareAnalysisPlanIsInjectedAndDeduplicatedWhenAvailable() {
        val playbook = validPlaybook().put(
            "initialTools",
            listOf(DeclareAnalysisPlanTool.NAME, "get_capture_overview")
        )
        val toolsWithPlanning = availableTools + DeclareAnalysisPlanTool.NAME

        val parsed = PlaybookParsing.parsePlaybook(playbook, toolsWithPlanning, "playbooks[0]")

        assertEquals(listOf(DeclareAnalysisPlanTool.NAME, "get_capture_overview"), parsed.initialTools)
    }

    private fun validPlaybook(): JSONObject =
        JSONObject(TestScenarioPackages.MINIMAL_PLAYBOOKS)
            .getJSONArray("playbooks")
            .getJSONObject(0)

    private companion object {
        val availableTools = TestScenarioPackages.availableTools
    }
}
