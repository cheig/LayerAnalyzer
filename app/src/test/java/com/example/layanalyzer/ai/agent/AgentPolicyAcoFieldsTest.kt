package com.example.layanalyzer.ai.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentPolicyAcoFieldsTest {
    @Test
    fun acoFieldDefaultsMatchDesignDocument() {
        val policy = AgentPolicy()

        assertEquals(AgentPolicy.DEFAULT_MAX_CRITIC_REQUESTS, policy.maxCriticRequests)
        assertEquals(1, policy.maxCriticRequests)
        assertEquals(
            AgentPolicy.DEFAULT_MAX_REVISION_REPAIR_STEPS,
            policy.maxRevisionRepairSteps
        )
        assertEquals(3, policy.maxRevisionRepairSteps)
        assertEquals(AgentPolicy.DEFAULT_MAX_REPLANS, policy.maxReplans)
        assertEquals(1, policy.maxReplans)
        assertTrue(policy.enforcePlaybookCheckCoverage)
        assertTrue(policy.quickModeEnabled)
        assertEquals(
            AgentPolicy.DEFAULT_MAX_SELF_CONSISTENCY_REQUESTS,
            policy.maxSelfConsistencyRequests
        )
        assertEquals(2, policy.maxSelfConsistencyRequests)
        assertEquals(
            AgentPolicy.DEFAULT_MAX_CONSECUTIVE_NON_PRODUCTIVE_TOOL_CALLS,
            policy.maxConsecutiveNonProductiveToolCalls
        )
        assertEquals(4, policy.maxConsecutiveNonProductiveToolCalls)
        assertEquals(2, policy.maxConcurrentDelegations)
    }

    @Test
    fun invalidAcoFieldValuesAreRejected() {
        assertTrue(runCatching { AgentPolicy(maxCriticRequests = -1) }.isFailure)
        assertTrue(
            runCatching {
                AgentPolicy(maxCriticRequests = AgentPolicy.MAX_CRITIC_REQUESTS + 1)
            }.isFailure
        )
        assertTrue(runCatching { AgentPolicy(maxRevisionRepairSteps = -1) }.isFailure)
        assertTrue(
            runCatching {
                AgentPolicy(maxRevisionRepairSteps = AgentPolicy.MAX_REVISION_REPAIR_STEPS + 1)
            }.isFailure
        )
        assertTrue(runCatching { AgentPolicy(maxReplans = -1) }.isFailure)
        assertTrue(
            runCatching { AgentPolicy(maxReplans = AgentPolicy.MAX_REPLANS + 1) }.isFailure
        )
        assertTrue(runCatching { AgentPolicy(maxSelfConsistencyRequests = -1) }.isFailure)
        assertTrue(
            runCatching {
                AgentPolicy(
                    maxSelfConsistencyRequests = AgentPolicy.MAX_SELF_CONSISTENCY_REQUESTS + 1
                )
            }.isFailure
        )
        assertTrue(
            runCatching { AgentPolicy(maxConsecutiveNonProductiveToolCalls = -1) }.isFailure
        )
        assertTrue(runCatching { AgentPolicy(maxConcurrentDelegations = 0) }.isFailure)
        assertTrue(
            runCatching {
                AgentPolicy(
                    maxConcurrentDelegations = AgentPolicy.MAX_CONCURRENT_DELEGATIONS + 1
                )
            }.isFailure
        )
    }

    @Test
    fun narrowedToTakesTheStricterValueOfEachAcoField() {
        val base = AgentPolicy(
            maxCriticRequests = 4,
            maxRevisionRepairSteps = 8,
            maxReplans = 2,
            enforcePlaybookCheckCoverage = true,
            quickModeEnabled = true,
            maxSelfConsistencyRequests = 4,
            maxConsecutiveNonProductiveToolCalls = 8,
            maxConcurrentDelegations = 4
        )
        val stricter = AgentPolicy(
            maxCriticRequests = 2,
            maxRevisionRepairSteps = 3,
            maxReplans = 1,
            enforcePlaybookCheckCoverage = true,
            quickModeEnabled = true,
            maxSelfConsistencyRequests = 2,
            maxConsecutiveNonProductiveToolCalls = 4,
            maxConcurrentDelegations = 2
        )

        val narrowed = base.narrowedTo(stricter)

        assertEquals(2, narrowed.maxCriticRequests)
        assertEquals(3, narrowed.maxRevisionRepairSteps)
        assertEquals(1, narrowed.maxReplans)
        assertTrue(narrowed.enforcePlaybookCheckCoverage)
        assertTrue(narrowed.quickModeEnabled)
        assertEquals(2, narrowed.maxSelfConsistencyRequests)
        assertEquals(4, narrowed.maxConsecutiveNonProductiveToolCalls)
        assertEquals(2, narrowed.maxConcurrentDelegations)
    }

    @Test
    fun narrowedToClosesBooleanGatesAndLetsZeroWin() {
        val permissive = AgentPolicy(
            enforcePlaybookCheckCoverage = true,
            quickModeEnabled = true,
            maxCriticRequests = 2
        )
        val strict = AgentPolicy(
            enforcePlaybookCheckCoverage = false,
            quickModeEnabled = false,
            maxCriticRequests = 0
        )

        val narrowed = permissive.narrowedTo(strict)

        assertFalse(narrowed.enforcePlaybookCheckCoverage)
        assertFalse(narrowed.quickModeEnabled)
        // Zero disables the Critic stage and wins the element-wise minimum.
        assertEquals(0, narrowed.maxCriticRequests)
        // The reverse direction keeps the gates closed too.
        assertFalse(strict.narrowedTo(permissive).enforcePlaybookCheckCoverage)
        assertFalse(strict.narrowedTo(permissive).quickModeEnabled)
        // A default policy keeps its own gates against a fully permissive side.
        val defaultNarrowed = AgentPolicy().narrowedTo(permissive)
        assertTrue(defaultNarrowed.enforcePlaybookCheckCoverage)
        assertTrue(defaultNarrowed.quickModeEnabled)
    }

    @Test
    fun preciseTruncationDowngradeDefaultsToOn() {
        assertTrue(AgentPolicy().preciseTruncationDowngrade)
    }

    @Test
    fun narrowedToClosesThePreciseTruncationGateInBothDirections() {
        val withGate = AgentPolicy(preciseTruncationDowngrade = true)
        val withoutGate = AgentPolicy(preciseTruncationDowngrade = false)

        assertFalse(withGate.narrowedTo(withoutGate).preciseTruncationDowngrade)
        assertFalse(withoutGate.narrowedTo(withGate).preciseTruncationDowngrade)
        assertTrue(withGate.narrowedTo(withGate).preciseTruncationDowngrade)
    }

    @Test
    fun findingPolarityNegativeValidationDefaultsToOn() {
        assertTrue(AgentPolicy().findingPolarityNegativeValidation)
    }

    @Test
    fun narrowedToClosesTheFindingPolarityValidationGateInBothDirections() {
        val withGate = AgentPolicy(findingPolarityNegativeValidation = true)
        val withoutGate = AgentPolicy(findingPolarityNegativeValidation = false)

        assertFalse(withGate.narrowedTo(withoutGate).findingPolarityNegativeValidation)
        assertFalse(withoutGate.narrowedTo(withGate).findingPolarityNegativeValidation)
        assertTrue(withGate.narrowedTo(withGate).findingPolarityNegativeValidation)
    }

    @Test
    fun enforceSignalCoverageDefaultsToOn() {
        assertTrue(AgentPolicy().enforceSignalCoverage)
    }

    @Test
    fun narrowedToClosesTheSignalCoverageGateInBothDirections() {
        val withGate = AgentPolicy(enforceSignalCoverage = true)
        val withoutGate = AgentPolicy(enforceSignalCoverage = false)

        assertFalse(withGate.narrowedTo(withoutGate).enforceSignalCoverage)
        assertFalse(withoutGate.narrowedTo(withGate).enforceSignalCoverage)
        assertTrue(withGate.narrowedTo(withGate).enforceSignalCoverage)
    }
}
