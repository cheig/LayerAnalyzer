package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentTokenUsage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentBudgetTrackerTest {
    @Test
    fun reserveConsumesStepsUpToTheLimit() {
        val tracker = AgentBudgetTracker(AgentPolicy(maxSteps = 3))

        repeat(3) { assertTrue(tracker.reserve().isSuccess) }
        val exhausted = tracker.reserve()

        assertTrue(exhausted.isFailure)
        assertEquals(
            AgentErrorCode.MAX_STEPS_REACHED,
            (exhausted.exceptionOrNull() as? AgentBudgetTracker.BudgetExceededException)?.agentError?.code
        )
        assertEquals(0, tracker.remainingSteps())
        assertTrue(tracker.isExhausted())
    }

    @Test
    fun detailFramesAreChargedOncePerSession() {
        val tracker = AgentBudgetTracker(
            AgentPolicy(maxSteps = 10, maxDetailFramesPerCall = 4, maxDetailFramesPerSession = 6)
        )

        assertTrue(tracker.reserve(listOf(1L, 2L, 3L)).isSuccess)
        assertTrue(tracker.reserve(listOf(1L, 2L, 3L)).isSuccess)
        assertEquals(3, tracker.usage().detailFrames)

        assertTrue(tracker.reserve(listOf(4L, 5L, 6L)).isSuccess)
        assertEquals(6, tracker.usage().detailFrames)

        // The session cap no longer rejects: it grants nothing and omits
        // everything, so the caller can report the quota honestly.
        val overQuota = tracker.reserve(listOf(7L)).getOrThrow()
        assertEquals(emptySet<Long>(), overQuota.grantedFrames)
        assertEquals(setOf(7L), overQuota.omittedFrames)
        assertTrue(overQuota.omittedBySessionQuota)
        assertEquals(0, overQuota.remainingSessionDetailFrames)
        assertEquals(6, tracker.usage().detailFrames)
    }

    @Test
    fun perCallDetailLimitGrantsAPrefixAndOmitsTheRest() {
        val tracker = AgentBudgetTracker(
            AgentPolicy(maxDetailFramesPerCall = 2, maxDetailFramesPerSession = 24)
        )

        val reservation = tracker.reserve(listOf(1L, 2L, 3L)).getOrThrow()

        assertEquals(setOf(1L, 2L), reservation.grantedFrames)
        assertEquals(setOf(3L), reservation.omittedFrames)
        assertFalse(reservation.omittedBySessionQuota)
        assertEquals(2, tracker.usage().detailFrames)
    }

    @Test
    fun framesCutByThePerCallCapAreNotChargedToTheSession() {
        val tracker = AgentBudgetTracker(
            AgentPolicy(maxSteps = 10, maxDetailFramesPerCall = 2, maxDetailFramesPerSession = 3)
        )

        val first = tracker.reserve(listOf(1L, 2L, 3L)).getOrThrow()
        assertEquals(setOf(1L, 2L), first.grantedFrames)
        assertEquals(setOf(3L), first.omittedFrames)
        // Only the granted pair was billed: one session slot remains.
        assertEquals(2, tracker.usage().detailFrames)
        assertEquals(1, first.remainingSessionDetailFrames)

        // The omitted frame can be read by a later call within the quota.
        val second = tracker.reserve(listOf(3L)).getOrThrow()
        assertEquals(setOf(3L), second.grantedFrames)
        assertEquals(emptySet<Long>(), second.omittedFrames)
        assertEquals(3, tracker.usage().detailFrames)

        // Now the session is full: even a single new frame grants nothing.
        val third = tracker.reserve(listOf(4L)).getOrThrow()
        assertEquals(emptySet<Long>(), third.grantedFrames)
        assertTrue(third.omittedBySessionQuota)
    }

    @Test
    fun perCallCapCedesItsSlotToAChargedFrameBehindAnUnaffordableOne() {
        val tracker = AgentBudgetTracker(
            AgentPolicy(maxSteps = 10, maxDetailFramesPerCall = 1, maxDetailFramesPerSession = 1)
        )

        // 1 fills the only session slot.
        assertTrue(tracker.reserve(listOf(1L)).isSuccess)

        // 2 is unaffordable, but 1 is already charged and still fits the call.
        val reservation = tracker.reserve(listOf(2L, 1L)).getOrThrow()
        assertEquals(setOf(1L), reservation.grantedFrames)
        assertEquals(setOf(2L), reservation.omittedFrames)
        assertTrue(reservation.omittedBySessionQuota)
    }

    @Test
    fun aPerCallOmissionIsNotReportedAsSessionExhaustion() {
        val tracker = AgentBudgetTracker(
            AgentPolicy(maxSteps = 10, maxDetailFramesPerCall = 2, maxDetailFramesPerSession = 3)
        )

        // 2 and 3 take two of the three session slots, leaving one.
        assertTrue(tracker.reserve(listOf(2L, 3L)).isSuccess)

        // 1 and 2 are granted: 1 takes the last session slot, 2 is free.  3 is
        // already charged, so only the per-call cap could have cut it — and the
        // flag must not call that session exhaustion.
        val reservation = tracker.reserve(listOf(1L, 2L, 3L)).getOrThrow()

        assertEquals(setOf(1L, 2L), reservation.grantedFrames)
        assertEquals(setOf(3L), reservation.omittedFrames)
        assertFalse(reservation.omittedBySessionQuota)
    }

    @Test
    fun elapsedRunTimeDoesNotExhaustTheStepBudget() {
        var now = 0L
        val tracker = AgentBudgetTracker(
            AgentPolicy(maxSteps = 3, maxModelRequestTimeoutMillis = 1_000L)
        ) { now }

        assertTrue(tracker.reserve().isSuccess)
        now = 1_500L

        assertTrue(tracker.reserve().isSuccess)
        assertEquals(2, tracker.usage().steps)
        assertFalse(tracker.isExhausted())
    }

    @Test
    fun resultByteAllowanceShrinksAsResultsAccumulate() {
        val policy = AgentPolicy(maxSteps = 4, maxToolResultBytes = 1_024, maxTotalResultBytes = 2_048L)
        val tracker = AgentBudgetTracker(policy)

        assertEquals(1_024, tracker.resultByteAllowance())
        tracker.recordResultBytes(1_500)
        assertEquals(548, tracker.resultByteAllowance())

        tracker.recordResultBytes(600)
        assertEquals(0, tracker.resultByteAllowance())
        assertTrue(tracker.reserve().isFailure)
    }

    @Test
    fun cachedInputUsesOneTenthWeightAndModelUsageResetsWithTheRun() {
        val tracker = AgentBudgetTracker(
            AgentPolicy(
                maxCumulativeInputTokens = 78L,
                maxCumulativeOutputTokens = 20L
            )
        )

        tracker.recordModelUsage(
            AgentTokenUsage(inputTokens = 100, cachedInputTokens = 80, outputTokens = 7)
        )
        var usage = tracker.usage()
        assertEquals(100L, usage.totalInputTokens)
        assertEquals(20L, usage.uncachedInputTokens)
        assertEquals(80L, usage.cachedInputTokens)
        assertEquals(0L, usage.cacheCreationTokens)
        assertEquals(28L, usage.weightedInputTokens)
        assertEquals(7L, usage.outputTokens)
        assertFalse(tracker.isModelBudgetExhausted())

        tracker.recordModelUsage(AgentTokenUsage(inputTokens = 50, outputTokens = 13))
        usage = tracker.usage()
        assertEquals(150L, usage.totalInputTokens)
        assertEquals(70L, usage.uncachedInputTokens)
        assertEquals(80L, usage.cachedInputTokens)
        assertEquals(78L, usage.weightedInputTokens)
        assertEquals(20L, usage.outputTokens)
        assertTrue(usage.inputTokensExhausted)
        assertTrue(usage.outputTokensExhausted)
        assertTrue(tracker.isModelBudgetExhausted())

        tracker.start()
        usage = tracker.usage()
        assertEquals(0L, usage.totalInputTokens)
        assertEquals(0L, usage.uncachedInputTokens)
        assertEquals(0L, usage.cachedInputTokens)
        assertEquals(0L, usage.cacheCreationTokens)
        assertEquals(0L, usage.weightedInputTokens)
        assertEquals(0L, usage.outputTokens)
    }

    @Test
    fun cacheCreationIsExposedSeparatelyAndKeepsFullInputWeight() {
        val tracker = AgentBudgetTracker(AgentPolicy())

        tracker.recordModelUsage(
            AgentTokenUsage(
                inputTokens = 100,
                cachedInputTokens = 40,
                cacheCreationTokens = 30,
                outputTokens = 9
            )
        )

        val usage = tracker.usage()
        assertEquals(100L, usage.totalInputTokens)
        assertEquals(30L, usage.uncachedInputTokens)
        assertEquals(40L, usage.cachedInputTokens)
        assertEquals(30L, usage.cacheCreationTokens)
        assertEquals(64L, usage.weightedInputTokens)
        assertEquals(9L, usage.outputTokens)
    }

    @Test
    fun anthropicStyleCacheReadCannotEscapeTheWeightedInputBudget() {
        val tracker = AgentBudgetTracker(AgentPolicy(maxCumulativeInputTokens = 18_821L))

        tracker.recordModelUsage(
            AgentTokenUsage(inputTokens = 188_021, cachedInputTokens = 188_000)
        )

        assertEquals(188_021L, tracker.usage().totalInputTokens)
        assertEquals(21L, tracker.usage().uncachedInputTokens)
        assertEquals(188_000L, tracker.usage().cachedInputTokens)
        assertEquals(18_821L, tracker.usage().weightedInputTokens)
        assertTrue(tracker.isModelBudgetExhausted())
    }

    @Test
    fun compactFieldRequestsCanUseTheDynamicDetailGrant() {
        val policy = AgentPolicy()

        val compact = policy.detailFrameGrant(
            AgentDetailRequest(
                fieldCount = 1,
                fieldNameChars = 10,
                includeDisplayValue = false
            )
        )
        val wide = policy.detailFrameGrant(
            AgentDetailRequest(
                fieldCount = 1,
                fieldNameChars = 10,
                includeDisplayValue = true
            )
        )

        assertEquals(24, compact.limit)
        assertEquals("dynamic_short_projection", compact.reason)
        assertEquals(16, wide.limit)
        assertEquals("wide_projection", wide.reason)
    }

    /** The device-observed failure shape: 16 fields with display values. */
    @Test
    fun wideProjectionsAreByteFittedToReturnCompleteFrames() {
        val policy = AgentPolicy()

        val grant = policy.detailFrameGrant(
            AgentDetailRequest(
                fieldCount = 16,
                fieldNameChars = 192,
                includeDisplayValue = true
            )
        )

        assertEquals("byte_fitted_projection", grant.reason)
        assertTrue("expected a shrunken grant, got ${grant.limit}", grant.limit in 1..8)
    }

    @Test
    fun byteFitIsDisabledWithTheDynamicGrantRollbackSwitch() {
        val policy = AgentPolicy(dynamicDetailFramesEnabled = false)

        val grant = policy.detailFrameGrant(
            AgentDetailRequest(
                fieldCount = 16,
                fieldNameChars = 192,
                includeDisplayValue = true
            )
        )

        assertEquals(16, grant.limit)
        assertEquals("default_projection", grant.reason)
    }

    @Test
    fun detailResultByteQuotaCanOmitFramesBeforeDissection() {
        val policy = AgentPolicy(
            maxSteps = 4,
            maxToolResultBytes = 512,
            maxDetailResultBytesPerCall = 512,
            maxDetailResultBytesPerSession = 512L
        )
        val tracker = AgentBudgetTracker(policy)
        tracker.recordResultBytes(512, detailRead = true)

        val reservation = tracker.reserve(listOf(1L, 2L)).getOrThrow()

        assertTrue(reservation.grantedFrames.isEmpty())
        assertEquals(setOf(1L, 2L), reservation.omittedFrames)
        assertTrue(reservation.omittedByResultByteQuota)
        assertEquals("detail_result_byte_quota", reservation.detailGrantReason)
        assertEquals(0L, reservation.remainingDetailResultBytes)
    }

    @Test
    fun totalByteLimitReportsContextLimit() {
        val tracker = AgentBudgetTracker(
            AgentPolicy(maxToolResultBytes = 512, maxTotalResultBytes = 512L)
        )
        tracker.recordResultBytes(512)

        val error = (tracker.reserve().exceptionOrNull() as? AgentBudgetTracker.BudgetExceededException)
            ?.agentError
        assertEquals(AgentErrorCode.CONTEXT_LIMIT, error?.code)
    }

    @Test
    fun startResetsEveryCounter() {
        var now = 0L
        val tracker = AgentBudgetTracker(AgentPolicy(maxSteps = 2), { now })
        tracker.reserve(listOf(1L))
        tracker.recordResultBytes(400)
        now = 5_000L

        tracker.start()

        val usage = tracker.usage()
        assertEquals(0, usage.steps)
        assertEquals(0, usage.detailFrames)
        assertEquals(0L, usage.resultBytes)
        assertEquals(0L, usage.elapsedMillis)
        assertFalse(tracker.isExhausted())
    }
}
