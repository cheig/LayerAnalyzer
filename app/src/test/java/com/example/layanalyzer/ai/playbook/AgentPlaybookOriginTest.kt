// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.playbook

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins the SRE-ARCH-02 contract for [AgentPlaybook.origin]: the default keeps
 * existing construction sites built-in, the field never travels through JSON
 * (the owning store assigns it), and [AgentPlaybook.promptSection] output does
 * not depend on it.
 */
class AgentPlaybookOriginTest {
    @Test
    fun directConstructionDefaultsToBuiltIn() {
        assertEquals(ScenarioOrigin.BuiltIn, AgentPlaybook.generalCaptureHealth().origin)
    }

    @Test
    fun decodedPackagePlaybooksAreBuiltIn() {
        val playbooks = AgentPlaybookStore.decode(playbooksJson, availableTools)

        assertTrue(playbooks.isNotEmpty())
        playbooks.forEach { playbook ->
            assertEquals(ScenarioOrigin.BuiltIn, playbook.origin)
        }
    }

    @Test
    fun originKeyInJsonIsRejected() {
        // requireExactKeys rejects unknown keys, so stored content can never
        // carry an origin: only the owning store assigns it.
        val json = """
            {"schemaVersion":2,"playbooks":[{
              "id":"general-capture-health","version":1,"title":"General capture health",
              "origin":"user",
              "intentHints":["capture health"],"protocols":["any"],
              "initialTools":["get_capture_overview"],"requiredFields":[],
              "checks":[{"id":"health","description":"Read the overview","recommendedTools":["get_statistics"]}],
              "successPath":["Read the overview first"],"failureBranches":[],
              "requiredLimitations":["Conclusions require tool evidence."],
              "outputSections":["summary","limitations"]
            }]}
        """.trimIndent()

        val failure = runCatching { AgentPlaybookStore.decode(json, availableTools) }

        assertTrue(failure.isFailure)
    }

    @Test
    fun promptSectionDoesNotDependOnOrigin() {
        val builtIn = AgentPlaybook.generalCaptureHealth()
        val userCopy = builtIn.copy(origin = ScenarioOrigin.User)

        assertEquals(builtIn.promptSection(), userCopy.promptSection())
    }

    private companion object {
        val playbooksJson: String = TestScenarioPackages.builtInAsset(
            VersionedScenarioPackageStore.PLAYBOOKS_FILE
        )
        val availableTools = TestScenarioPackages.availableTools
    }
}
