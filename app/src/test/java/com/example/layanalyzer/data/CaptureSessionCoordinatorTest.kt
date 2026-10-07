// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.DisplayFilterResult
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.FileSessionInfo
import com.example.layanalyzer.model.FollowStreamResult
import com.example.layanalyzer.model.PacketSearchMode
import com.example.layanalyzer.model.PacketSummary
import com.example.layanalyzer.model.ProtocolNode
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class CaptureSessionCoordinatorTest {
    @Test
    fun agentNativeReadsRunOffTheCallerThread() = runBlocking {
        val harness = readyHarness(originalFilter = "")
        try {
            val caller = Thread.currentThread().name
            val result = harness.agentRepository.getStatistics(harness.snapshot)

            assertTrue(result.success)
            assertNotEquals(caller, harness.source.lastNativeReadThread)
        } finally {
            harness.close()
        }
    }

    @Test
    fun deterministicAnalysisIsReusedForTheSameSnapshotAndFilter() = runBlocking {
        val harness = readyHarness(originalFilter = "")
        try {
            assertTrue(harness.agentRepository.getCommunicationAnalysis(harness.snapshot).success)
            assertTrue(harness.agentRepository.getCommunicationAnalysis(harness.snapshot).success)

            assertEquals(1, harness.source.communicationAnalysisCalls)
        } finally {
            harness.close()
        }
    }

    @Test
    fun temporaryFilterRestoresExpressionAndVisibleCount() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            val revision = harness.coordinator.state.value.filterRevision
            val result = harness.agentRepository.queryWithTemporaryFilter(
                harness.snapshot,
                "tcp"
            ) { reader ->
                reader.getVisibleFrameCount()
            }

            assertTrue(result.success)
            assertEquals(2, result.getOrNull())
            assertEquals("udp", harness.source.activeFilter)
            assertEquals(4, harness.source.visibleCount)
            assertEquals("udp", harness.coordinator.state.value.appliedDisplayFilter)
            assertEquals(4, harness.coordinator.state.value.visibleFrameCount)
            assertEquals(revision, harness.coordinator.state.value.filterRevision)
        } finally {
            harness.close()
        }
    }

    @Test
    fun invalidTemporaryFilterDoesNotModifyUserFilter() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            harness.source.invalidFilters += "invalid["
            val applyCount = harness.source.applyCalls.size

            val result = harness.agentRepository.queryWithTemporaryFilter(
                harness.snapshot,
                "invalid["
            ) { it.getVisibleFrameCount() }

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_DISPLAY_FILTER, result.errorOrNull()?.code)
            assertEquals(applyCount, harness.source.applyCalls.size)
            assertEquals("udp", harness.source.activeFilter)
            assertEquals(4, harness.source.visibleCount)
        } finally {
            harness.close()
        }
    }

    @Test
    fun userFilterWaitsUntilAgentLeaseRestores() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val agent = async(Dispatchers.Default) {
                harness.agentRepository.queryWithTemporaryFilter(harness.snapshot, "tcp") {
                    entered.complete(Unit)
                    release.await()
                    it.getVisibleFrameCount()
                }
            }
            entered.await()

            val user = async(Dispatchers.Default) {
                harness.coordinator.applyUserFilter("dns", harness.token)
            }
            yield()
            delay(25)
            assertEquals("tcp", harness.source.activeFilter)
            assertFalse(harness.source.applyCalls.any { it.second == "dns" })

            release.complete(Unit)
            assertTrue(agent.await().success)
            assertTrue(user.await().success)
            assertEquals(listOf("tcp", "udp", "dns"), harness.source.applyCalls.takeLast(3).map { it.second })
            assertEquals("dns", harness.source.activeFilter)
        } finally {
            harness.close()
        }
    }

    @Test
    fun switchingSessionDiscardsResultAndNeverRestoresOldFilterToNewSession() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        val replacement = File.createTempFile("layer-analyzer-session-b", ".pcap")
        try {
            replacement.writeText("session-b")
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val agent = async(Dispatchers.Default) {
                harness.agentRepository.queryWithTemporaryFilter(harness.snapshot, "tcp") {
                    entered.complete(Unit)
                    release.await()
                    it.getVisibleFrameCount()
                }
            }
            entered.await()

            harness.coordinator.invalidateSession()
            harness.source.switchSession(2L, replacement)
            val newToken = harness.coordinator.onSessionOpened(harness.source.currentFile()!!)
            assertTrue(harness.coordinator.prepareFingerprint(newToken, replacement).isSuccess)
            release.complete(Unit)

            val result = agent.await()
            assertFalse(result.success)
            assertEquals(AgentErrorCode.SESSION_CHANGED, result.errorOrNull()?.code)
            assertFalse(harness.source.applyCalls.any { it.first == 2L && it.second == "udp" })
            assertEquals("", harness.source.activeFilter)
        } finally {
            replacement.delete()
            harness.close()
        }
    }

    @Test
    fun exceptionsTimeoutsAndCancellationAllRestoreInFinally() = runBlocking {
        val failureHarness = readyHarness(originalFilter = "udp")
        try {
            val failure = failureHarness.agentRepository.queryWithTemporaryFilter(
                failureHarness.snapshot,
                "tcp"
            ) { error("tool failed") }
            assertEquals(AgentErrorCode.INTERNAL_ERROR, failure.errorOrNull()?.code)
            assertEquals("udp", failureHarness.source.activeFilter)
        } finally {
            failureHarness.close()
        }

        val timeoutHarness = readyHarness(originalFilter = "udp", maxLeaseMillis = 20L)
        try {
            val timeout = timeoutHarness.agentRepository.queryWithTemporaryFilter(
                timeoutHarness.snapshot,
                "tcp"
            ) {
                delay(100L)
                it.getVisibleFrameCount()
            }
            assertEquals(AgentErrorCode.TOOL_TIMEOUT, timeout.errorOrNull()?.code)
            assertEquals("udp", timeoutHarness.source.activeFilter)
        } finally {
            timeoutHarness.close()
        }

        val cancellationHarness = readyHarness(originalFilter = "udp")
        try {
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val running = async(Dispatchers.Default) {
                cancellationHarness.agentRepository.queryWithTemporaryFilter(
                    cancellationHarness.snapshot,
                    "tcp"
                ) {
                    entered.complete(Unit)
                    release.await()
                    it.getVisibleFrameCount()
                }
            }
            entered.await()
            cancellationHarness.agentRepository.cancelLongRunningOperations()
            release.complete(Unit)
            val cancelled = running.await()
            assertEquals(AgentErrorCode.CANCELLED, cancelled.errorOrNull()?.code)
            assertEquals("udp", cancellationHarness.source.activeFilter)
        } finally {
            cancellationHarness.close()
        }
    }

    @Test
    fun failedRestoreReturnsFilterConflictAndPublishesActualState() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            harness.source.failNextRestoreOf = "udp"
            val refresh = async(start = CoroutineStart.UNDISPATCHED) {
                harness.coordinator.filterRefreshEvents.first()
            }

            val result = harness.agentRepository.queryWithTemporaryFilter(
                harness.snapshot,
                "tcp"
            ) { it.getVisibleFrameCount() }

            assertFalse(result.success)
            assertEquals(AgentErrorCode.FILTER_CONFLICT, result.errorOrNull()?.code)
            assertEquals(AgentErrorCode.FILTER_CONFLICT, refresh.await().reason)
            assertEquals("tcp", harness.source.activeFilter)
            assertEquals("tcp", harness.coordinator.state.value.appliedDisplayFilter)
            assertEquals(2, harness.coordinator.state.value.visibleFrameCount)
        } finally {
            harness.close()
        }
    }

    @Test
    fun chainedAgentReadsKeepTemporaryFilterAndRestoreOnceAtChainEnd() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            val revision = harness.coordinator.state.value.filterRevision
            harness.coordinator.beginAgentFilterChain()
            val first = harness.agentRepository.queryWithTemporaryFilter(
                harness.snapshot,
                "tcp"
            ) { it.getVisibleFrameCount() }
            val second = harness.agentRepository.queryWithTemporaryFilter(
                harness.snapshot,
                "dns"
            ) { it.getVisibleFrameCount() }
            harness.coordinator.endAgentFilterChain()

            assertTrue(first.success)
            assertTrue(second.success)
            // No restore between chained reads: the native session went tcp -> dns.
            assertEquals(
                listOf("udp", "tcp", "dns", "udp"),
                harness.source.applyCalls.map { it.second }
            )
            assertEquals("udp", harness.source.activeFilter)
            assertEquals(4, harness.source.visibleCount)
            assertEquals("udp", harness.coordinator.state.value.appliedDisplayFilter)
            assertEquals(4, harness.coordinator.state.value.visibleFrameCount)
            assertEquals(revision, harness.coordinator.state.value.filterRevision)
        } finally {
            harness.close()
        }
    }

    @Test
    fun userFilterApplicationInsideChainDropsPendingRestore() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            harness.coordinator.beginAgentFilterChain()
            harness.agentRepository.queryWithTemporaryFilter(
                harness.snapshot,
                "tcp"
            ) { it.getVisibleFrameCount() }
            assertTrue(harness.coordinator.applyUserFilter("dns", harness.token).success)
            assertEquals(
                listOf("udp", "tcp", "dns"),
                harness.source.applyCalls.map { it.second }
            )
            harness.coordinator.endAgentFilterChain()

            // The user's apply replaced the Agent view, so the chain end is a no-op.
            assertEquals(
                listOf("udp", "tcp", "dns"),
                harness.source.applyCalls.map { it.second }
            )
            assertEquals("dns", harness.source.activeFilter)
        } finally {
            harness.close()
        }
    }

    @Test
    fun failedUserApplyInsideChainRestoresUserView() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            harness.coordinator.beginAgentFilterChain()
            harness.agentRepository.queryWithTemporaryFilter(
                harness.snapshot,
                "tcp"
            ) { it.getVisibleFrameCount() }
            harness.source.failedApplies["dns"] = 1

            val result = harness.coordinator.applyUserFilter("dns", harness.token)

            assertFalse(result.success)
            // The user's own view comes back when their apply fails, instead of
            // leaving the Agent's temporary filter in the session.
            assertEquals(
                listOf("udp", "tcp", "dns", "udp"),
                harness.source.applyCalls.map { it.second }
            )
            assertEquals("udp", harness.source.activeFilter)
            harness.coordinator.endAgentFilterChain()
            assertEquals(
                listOf("udp", "tcp", "dns", "udp"),
                harness.source.applyCalls.map { it.second }
            )
        } finally {
            harness.close()
        }
    }

    @Test
    fun chainEndRetriesCancelledRestoreUntilItSucceeds() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            harness.coordinator.beginAgentFilterChain()
            harness.agentRepository.queryWithTemporaryFilter(
                harness.snapshot,
                "tcp"
            ) { it.getVisibleFrameCount() }
            harness.source.cancelledApplies["udp"] = 2

            harness.coordinator.endAgentFilterChain()

            // Two cancelled attempts leave the filter untouched, the third one
            // restores it instead of reporting FILTER_CONFLICT.
            assertEquals(0, harness.source.cancelledApplies["udp"])
            assertEquals("udp", harness.source.activeFilter)
            assertEquals(4, harness.source.visibleCount)
            assertEquals(
                listOf("udp", "tcp", "udp", "udp", "udp"),
                harness.source.applyCalls.map { it.second }
            )
        } finally {
            harness.close()
        }
    }

    @Test
    fun nestedChainsRestoreOnlyWhenTheLastOneEnds() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            harness.coordinator.beginAgentFilterChain()
            harness.coordinator.beginAgentFilterChain()
            harness.agentRepository.queryWithTemporaryFilter(
                harness.snapshot,
                "tcp"
            ) { it.getVisibleFrameCount() }

            harness.coordinator.endAgentFilterChain()
            assertEquals("tcp", harness.source.activeFilter)

            harness.coordinator.endAgentFilterChain()
            assertEquals("udp", harness.source.activeFilter)
        } finally {
            harness.close()
        }
    }

    @Test
    fun unbalancedChainEndWithoutPendingLeaseIsSafe() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            harness.coordinator.endAgentFilterChain()
            harness.coordinator.beginAgentFilterChain()
            harness.coordinator.endAgentFilterChain()

            assertEquals("udp", harness.source.activeFilter)
            assertEquals(listOf("udp"), harness.source.applyCalls.map { it.second })
        } finally {
            harness.close()
        }
    }

    @Test
    fun fingerprintFailureIsStructuredAndNeverBecomesEmptyIdentity() = runBlocking {
        val source = FakeCaptureDataSource()
        val file = File.createTempFile("layer-analyzer-fingerprint-failure", ".pcap")
        try {
            source.switchSession(1L, file)
            val coordinator = CaptureSessionCoordinator(
                dataSource = source,
                fingerprintCalculator = object : CaptureFingerprintCalculator() {
                    override fun calculate(file: File): String = error("hash unavailable")
                },
                fingerprintDispatcher = Dispatchers.Unconfined
            )
            val token = coordinator.onSessionOpened(source.currentFile()!!)
            assertTrue(coordinator.prepareFingerprint(token, file).isFailure)

            val result = AgentAnalysisRepository(source, coordinator)
                .createSnapshot(AnalysisScope.CompleteFile)
            assertFalse(result.success)
            assertEquals(AgentErrorCode.INTERNAL_ERROR, result.errorOrNull()?.code)
            assertTrue(coordinator.state.value.fileFingerprint.isBlank())
            assertEquals(CaptureFingerprintState.Failed, coordinator.state.value.fingerprintState)
        } finally {
            file.delete()
        }
    }

    // AI-24 section 4: analysisConfigVersion is a tool-cache key component, so
    // its behaviour across configuration changes and session swaps is what
    // decides whether a stale dissection can be served as current.

    @Test
    fun analysisConfigVersionStartsAtTheBaselineAndAdvancesOnConfigurationChange() = runBlocking {
        val harness = readyHarness(originalFilter = "")
        try {
            assertEquals(1, harness.coordinator.state.value.analysisConfigVersion)

            harness.coordinator.bumpAnalysisConfigVersion()

            assertEquals(2, harness.coordinator.state.value.analysisConfigVersion)
        } finally {
            harness.close()
        }
    }

    @Test
    fun analysisConfigVersionSurvivesAnInvalidateSoAStaleEntryCannotLookCurrent() = runBlocking {
        val harness = readyHarness(originalFilter = "")
        try {
            harness.coordinator.bumpAnalysisConfigVersion()
            harness.coordinator.bumpAnalysisConfigVersion()

            // Closing the native session must not roll the version back: the
            // cache entries written at version 3 still exist on disk.
            harness.coordinator.invalidateSession()

            assertEquals(3, harness.coordinator.state.value.analysisConfigVersion)
        } finally {
            harness.close()
        }
    }

    @Test
    fun reopeningACaptureReturnsToTheBaselineBecauseDecodeAsRulesAreCleared() = runBlocking {
        val harness = readyHarness(originalFilter = "")
        try {
            harness.coordinator.bumpAnalysisConfigVersion()
            assertEquals(2, harness.coordinator.state.value.analysisConfigVersion)

            // Opening a file resets the engine's Decode As rules, so the
            // dissection configuration is the default one again and the
            // baseline version comes back with it -- which is what lets the
            // capture reuse the results cached for it before.
            val reopened = harness.coordinator.onSessionOpened(harness.source.currentFile()!!)
            check(harness.coordinator.prepareFingerprint(reopened, harness.file).isSuccess)

            assertEquals(1, harness.coordinator.state.value.analysisConfigVersion)
        } finally {
            harness.close()
        }
    }

    @Test
    fun theSnapshotCarriesTheConfigurationVersionInForceWhenItWasTaken() = runBlocking {
        val harness = readyHarness(originalFilter = "")
        try {
            harness.coordinator.bumpAnalysisConfigVersion()
            val snapshot = checkNotNull(
                harness.agentRepository.createSnapshot(AnalysisScope.CompleteFile).getOrNull()
            )

            assertEquals(2, snapshot.analysisConfigVersion)
        } finally {
            harness.close()
        }
    }

    // EVL-FILTER-03: withTemporaryFilter borrows the Agent lease protocol for
    // non-Agent callers (the evidence-frame export), so an export never has to
    // build an Agent snapshot or restore the filter on its own.  Concurrency,
    // exception and session-change paths are EVL-FILTER-04's scope.

    @Test
    fun temporaryFilterRestoresUserViewAndKeepsFilterRevision() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            val revision = harness.coordinator.state.value.filterRevision

            val result = harness.coordinator.withTemporaryFilter("tcp") {
                harness.source.getVisibleFrameCount()
            }

            assertTrue(result.success)
            assertEquals(2, result.getOrNull())
            // The "udp" view is back on the native session and in published
            // state, and the revision did not move because a temporary swap is
            // not a user filter change.
            assertEquals("udp", harness.source.activeFilter)
            assertEquals(4, harness.source.visibleCount)
            assertEquals("udp", harness.coordinator.state.value.appliedDisplayFilter)
            assertEquals(4, harness.coordinator.state.value.visibleFrameCount)
            assertEquals(revision, harness.coordinator.state.value.filterRevision)
        } finally {
            harness.close()
        }
    }

    @Test
    fun temporaryFilterWithoutSessionFailsClosedWithNoCapture() = runBlocking {
        val source = FakeCaptureDataSource()
        val coordinator = CaptureSessionCoordinator(
            dataSource = source,
            fingerprintDispatcher = Dispatchers.Unconfined
        )

        val result = coordinator.withTemporaryFilter("tcp") {
            source.getVisibleFrameCount()
        }

        assertFalse(result.success)
        assertEquals(AgentErrorCode.NO_CAPTURE, result.errorOrNull()?.code)
        // Failing closed means the session check happens before any native
        // filter mutation, not after.
        assertTrue(source.applyCalls.isEmpty())
    }

    @Test
    fun temporaryFilterWithoutSessionNeverEntersTheBlock() = runBlocking {
        val source = FakeCaptureDataSource()
        val coordinator = CaptureSessionCoordinator(
            dataSource = source,
            fingerprintDispatcher = Dispatchers.Unconfined
        )
        var blockRan = false

        val result = coordinator.withTemporaryFilter("tcp") {
            blockRan = true
            source.getVisibleFrameCount()
        }

        assertFalse(result.success)
        assertEquals(AgentErrorCode.NO_CAPTURE, result.errorOrNull()?.code)
        assertFalse(blockRan)
    }

    // EVL-FILTER-04: the export lease must behave exactly like the Agent lease
    // on the concurrency, session-change, failure and cancellation paths, and
    // must not introduce a second restore path next to restoreLease.

    @Test
    fun temporaryFilterLeaseAppliesOnceRestoresOnceAndKeepsTheUserView() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            val revision = harness.coordinator.state.value.filterRevision

            val result = harness.coordinator.withTemporaryFilter("tcp") {
                harness.source.getVisibleFrameCount()
            }

            assertTrue(result.success)
            assertEquals(2, result.getOrNull())
            assertEquals("udp", harness.source.activeFilter)
            assertEquals(4, harness.source.visibleCount)
            assertEquals("udp", harness.coordinator.state.value.appliedDisplayFilter)
            assertEquals(revision, harness.coordinator.state.value.filterRevision)
            // The whole native apply history: the harness' initial user filter,
            // one temporary apply and one restore.  A second restore path would
            // show up here as an extra "udp".
            assertEquals(
                listOf("udp", "tcp", "udp"),
                harness.source.applyCalls.map { it.second }
            )
        } finally {
            harness.close()
        }
    }

    @Test
    fun temporaryFilterSerializesWithAConcurrentAgentFilterWithoutCrossRestore() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val export = async(Dispatchers.Default) {
                harness.coordinator.withTemporaryFilter("tcp") {
                    entered.complete(Unit)
                    release.await()
                    harness.source.getVisibleFrameCount()
                }
            }
            entered.await()

            val analysis = async(Dispatchers.Default) {
                harness.coordinator.withAgentFilter(harness.snapshot, "dns") {
                    harness.source.getVisibleFrameCount()
                }
            }
            yield()
            delay(25)
            // The Agent filter is not applied while the export holds the lease:
            // serialization is on filterMutex, not on a delay.
            assertFalse(harness.source.applyCalls.any { it.second == "dns" })
            assertEquals("tcp", harness.source.activeFilter)

            release.complete(Unit)
            assertTrue(export.await().success)
            assertTrue(analysis.await().success)

            // The export restores the user view before the Agent's apply can
            // start, and the Agent's own restore closes it: no interleaving and
            // no restore landing on top of the other lease's filter.
            assertEquals(
                listOf("udp", "tcp", "udp", "dns", "udp"),
                harness.source.applyCalls.map { it.second }
            )
            assertEquals("udp", harness.source.activeFilter)
            assertEquals(4, harness.source.visibleCount)
            assertEquals("udp", harness.coordinator.state.value.appliedDisplayFilter)
        } finally {
            harness.close()
        }
    }

    @Test
    fun temporaryFilterLeaseDropsTheRestoreWhenTheSessionChanges() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        val replacement = File.createTempFile("layer-analyzer-session-export", ".pcap")
        try {
            replacement.writeText("session-export")
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val export = async(Dispatchers.Default) {
                harness.coordinator.withTemporaryFilter("tcp") {
                    entered.complete(Unit)
                    release.await()
                    harness.source.getVisibleFrameCount()
                }
            }
            entered.await()

            harness.coordinator.invalidateSession()
            harness.source.switchSession(2L, replacement)
            val newToken = harness.coordinator.onSessionOpened(harness.source.currentFile()!!)
            assertTrue(harness.coordinator.prepareFingerprint(newToken, replacement).isSuccess)
            release.complete(Unit)

            val result = export.await()
            assertFalse(result.success)
            assertEquals(AgentErrorCode.SESSION_CHANGED, result.errorOrNull()?.code)
            // The old session's "udp" must never be applied to the replacement.
            assertFalse(harness.source.applyCalls.any { it.first == 2L && it.second == "udp" })
            assertEquals("", harness.source.activeFilter)
        } finally {
            replacement.delete()
            harness.close()
        }
    }

    @Test
    fun temporaryFilterRestoresTheUserViewWhenTheBlockThrows() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            val result = harness.coordinator.withTemporaryFilter("tcp") {
                error("export failed")
            }

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INTERNAL_ERROR, result.errorOrNull()?.code)
            assertEquals("udp", harness.source.activeFilter)
            assertEquals(4, harness.source.visibleCount)
            assertEquals("udp", harness.coordinator.state.value.appliedDisplayFilter)
        } finally {
            harness.close()
        }
    }

    @Test
    fun temporaryFilterRestoresTheUserViewWhenTheLeaseTimesOut() = runBlocking {
        val harness = readyHarness(originalFilter = "udp", maxLeaseMillis = 20L)
        try {
            val result = harness.coordinator.withTemporaryFilter("tcp") {
                delay(100L)
                harness.source.getVisibleFrameCount()
            }

            assertFalse(result.success)
            assertEquals(AgentErrorCode.TOOL_TIMEOUT, result.errorOrNull()?.code)
            assertEquals("udp", harness.source.activeFilter)
            assertEquals(4, harness.source.visibleCount)
            assertEquals("udp", harness.coordinator.state.value.appliedDisplayFilter)
        } finally {
            harness.close()
        }
    }

    @Test
    fun temporaryFilterRestoresTheUserViewWhenItsCoroutineIsCancelled() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            val entered = CompletableDeferred<Unit>()
            val neverReleased = CompletableDeferred<Unit>()
            val outcome = CompletableDeferred<AgentAnalysisResult<Int>>()
            val job = launch(Dispatchers.Default) {
                val result = harness.coordinator.withTemporaryFilter("tcp") {
                    entered.complete(Unit)
                    neverReleased.await()
                    harness.source.getVisibleFrameCount()
                }
                outcome.complete(result)
            }
            entered.await()

            job.cancelAndJoin()

            // The restore runs from NonCancellable, so the cancellation tearing
            // the coroutine down cannot swallow it.
            val result = outcome.await()
            assertFalse(result.success)
            assertEquals(AgentErrorCode.CANCELLED, result.errorOrNull()?.code)
            assertEquals("udp", harness.source.activeFilter)
            assertEquals(4, harness.source.visibleCount)
            assertEquals("udp", harness.coordinator.state.value.appliedDisplayFilter)
        } finally {
            harness.close()
        }
    }

    @Test
    fun filterOwnerReportsTheLeaseKindAndReturnsToNone() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            assertEquals(CaptureFilterOwner.None, harness.coordinator.filterOwner.value)

            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val export = async(Dispatchers.Default) {
                harness.coordinator.withTemporaryFilter("tcp") {
                    entered.complete(Unit)
                    release.await()
                    harness.source.getVisibleFrameCount()
                }
            }
            entered.await()
            assertEquals(CaptureFilterOwner.UserExport, harness.coordinator.filterOwner.value)
            release.complete(Unit)
            assertTrue(export.await().success)
            assertEquals(CaptureFilterOwner.None, harness.coordinator.filterOwner.value)

            val agentEntered = CompletableDeferred<Unit>()
            val agentRelease = CompletableDeferred<Unit>()
            val analysis = async(Dispatchers.Default) {
                harness.coordinator.withAgentFilter(harness.snapshot, "tcp") {
                    agentEntered.complete(Unit)
                    agentRelease.await()
                    harness.source.getVisibleFrameCount()
                }
            }
            agentEntered.await()
            assertEquals(CaptureFilterOwner.Agent, harness.coordinator.filterOwner.value)
            agentRelease.complete(Unit)
            assertTrue(analysis.await().success)
            assertEquals(CaptureFilterOwner.None, harness.coordinator.filterOwner.value)
        } finally {
            harness.close()
        }
    }

    @Test
    fun temporaryFilterRestoreFailureReusesTheFilterConflictPath() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            harness.source.failNextRestoreOf = "udp"
            val refresh = async(start = CoroutineStart.UNDISPATCHED) {
                harness.coordinator.filterRefreshEvents.first()
            }

            val result = harness.coordinator.withTemporaryFilter("tcp") {
                harness.source.getVisibleFrameCount()
            }

            assertFalse(result.success)
            assertEquals(AgentErrorCode.FILTER_CONFLICT, result.errorOrNull()?.code)
            // The export lease reports through the one existing conflict
            // channel, not a second restore/reporting path of its own.
            assertEquals(AgentErrorCode.FILTER_CONFLICT, refresh.await().reason)
        } finally {
            harness.close()
        }
    }

    @Test
    fun consecutiveTemporaryFilterLeasesEachSwapAndRestoreExactlyOnce() = runBlocking {
        val harness = readyHarness(originalFilter = "udp")
        try {
            val first = harness.coordinator.withTemporaryFilter("tcp") {
                harness.source.getVisibleFrameCount()
            }
            val second = harness.coordinator.withTemporaryFilter("dns") {
                harness.source.getVisibleFrameCount()
            }

            assertTrue(first.success)
            assertTrue(second.success)
            // Exactly one apply and one restore per lease.  An implementation
            // with its own private save/restore on top of the shared lease path
            // would add a second "udp" here.
            assertEquals(
                listOf("udp", "tcp", "udp", "dns", "udp"),
                harness.source.applyCalls.map { it.second }
            )
            assertEquals("udp", harness.source.activeFilter)
            assertEquals(4, harness.source.visibleCount)
            assertEquals("udp", harness.coordinator.state.value.appliedDisplayFilter)
        } finally {
            harness.close()
        }
    }

    @Test
    fun noSecondRestorePathIsIntroducedIntoTheCoordinator() {
        val file = coordinatorSourceFile()
        val lines = sourceCodeLines(file)
        val code = lines.joinToString("\n") { it.text }

        // The saved user filter is handed back to the native session in exactly
        // one place.  A second call site is the "second restore path" the
        // design forbids, because it is what strands the user's view.
        val restoreApply = Regex(
            """dataSource\s*\.\s*applyDisplayFilter\s*\(\s*lease\s*\.\s*originalDisplayFilter"""
        )
        val hits = restoreApply.findAll(code).toList()
        assertEquals(
            buildString {
                append("Expected exactly one dataSource.applyDisplayFilter(lease.originalDisplayFilter...) ")
                append("call in CaptureSessionCoordinator.kt but found ${hits.size}:")
                hits.forEach { append("\n  line ").append(lineNumberAt(lines, it.range.first)).append(": ").append(it.value) }
            },
            1,
            hits.size
        )

        // restoreLease itself may only be reached from releasePendingAgentLease
        // and the withFilterLease finally.  Any third caller is a second path.
        val callers = mutableListOf<String>()
        lines.forEachIndexed { index, line ->
            val trimmed = line.text.trim()
            if (trimmed.startsWith("private suspend fun restoreLease") ||
                trimmed.startsWith("fun restoreLease")
            ) {
                return@forEachIndexed
            }
            if (Regex("""\brestoreLease\s*\(""").find(line.text) != null) {
                callers += enclosingFunction(lines, index) ?: "<top-level line ${line.number}>"
            }
        }
        assertEquals(
            "restoreLease must only be called from releasePendingAgentLease and withFilterLease",
            listOf("releasePendingAgentLease", "withFilterLease"),
            callers
        )
    }

    /** Locate the coordinator source from wherever Gradle set the test working directory. */
    private fun coordinatorSourceFile(): File {
        val relative = "src/main/java/com/example/layanalyzer/data/CaptureSessionCoordinator.kt"
        val tried = mutableListOf<String>()
        var directory: File? = File("").absoluteFile
        while (directory != null) {
            listOf(File(directory, relative), File(directory, "app/$relative")).forEach { candidate ->
                tried += candidate.path
                if (candidate.isFile) return candidate
            }
            directory = directory.parentFile
        }
        throw AssertionError(
            "CaptureSessionCoordinator.kt not found from ${File("").absolutePath}. Tried:\n" +
                tried.joinToString("\n")
        )
    }

    /** A line of the coordinator's source, keeping its real 1-based file number. */
    private class SourceLine(val number: Int, val text: String)

    /** Code lines only, so a comment mentioning a symbol cannot satisfy a scan. */
    private fun sourceCodeLines(file: File): List<SourceLine> =
        file.readLines()
            .withIndex()
            .map { (index, raw) -> SourceLine(index + 1, raw.substringBefore("//")) }
            .filter { line ->
                val trimmed = line.text.trim()
                trimmed.isNotEmpty() &&
                    !trimmed.startsWith("*") &&
                    !trimmed.startsWith("/*")
            }

    private fun enclosingFunction(lines: List<SourceLine>, callIndex: Int): String? {
        // Tolerate a generic type parameter list (fun <T> withFilterLease), which
        // is what the shared lease helper is declared with.
        val declaration = Regex("""\bfun\s+(?:<[^>]*>\s*)?([A-Za-z_][A-Za-z0-9_]*)""")
        for (index in callIndex downTo 0) {
            val match = declaration.find(lines[index].text) ?: continue
            return match.groupValues[1]
        }
        return null
    }

    private fun lineNumberAt(lines: List<SourceLine>, charOffset: Int): Int {
        var remaining = charOffset
        lines.forEach { line ->
            val length = line.text.length + 1
            if (remaining < length) return line.number
            remaining -= length
        }
        return lines.lastOrNull()?.number ?: 0
    }

    private suspend fun readyHarness(
        originalFilter: String,
        maxLeaseMillis: Long = 30_000L
    ): Harness {        val source = FakeCaptureDataSource()
        val file = File.createTempFile("layer-analyzer-session-a", ".pcap")
        file.writeText("session-a")
        source.switchSession(1L, file)
        val coordinator = CaptureSessionCoordinator(
            dataSource = source,
            fingerprintCalculator = object : CaptureFingerprintCalculator() {
                override fun calculate(file: File): String = "sha-${file.name}"
            },
            fingerprintDispatcher = Dispatchers.Unconfined,
            maxAgentLeaseMillis = maxLeaseMillis
        )
        val token = coordinator.onSessionOpened(source.currentFile()!!)
        check(coordinator.prepareFingerprint(token, file).isSuccess)
        check(coordinator.applyUserFilter(originalFilter, token).success)
        val repository = AgentAnalysisRepository(source, coordinator)
        val snapshot = checkNotNull(
            repository.createSnapshot(AnalysisScope.CompleteFile).getOrNull()
        )
        return Harness(source, coordinator, repository, token, snapshot, file)
    }

    private data class Harness(
        val source: FakeCaptureDataSource,
        val coordinator: CaptureSessionCoordinator,
        val agentRepository: AgentAnalysisRepository,
        val token: CaptureSessionToken,
        val snapshot: com.example.layanalyzer.model.AgentCaptureSnapshot,
        val file: File
    ) : AutoCloseable {
        override fun close() {
            coordinator.invalidateSession()
            source.closeSession()
            file.delete()
        }
    }

    private class FakeCaptureDataSource : CaptureSessionDataSource, AgentReadSession {
        var handle: Long = 0L
        var totalFrames: Int = 10
        var visibleCount: Int = 10
        var activeFilter: String = ""
        var fileInfo: FileSessionInfo? = null
        val invalidFilters = mutableSetOf<String>()
        val applyCalls = mutableListOf<Pair<Long, String>>()
        var failNextRestoreOf: String? = null

        /** filter -> remaining applies that fail as cancelled, leaving state untouched. */
        val cancelledApplies = mutableMapOf<String, Int>()

        /** filter -> remaining applies that fail outright, leaving state untouched. */
        val failedApplies = mutableMapOf<String, Int>()
        private var temporaryFilterApplied = false
        var lastNativeReadThread: String? = null
        var communicationAnalysisCalls: Int = 0

        override fun currentSessionHandle(): Long = handle

        override fun currentFile(): FileSessionInfo? = fileInfo

        override fun getFrameCount(): Int = if (handle == 0L) 0 else totalFrames

        override fun getVisibleFrameCount(): Int = if (handle == 0L) 0 else visibleCount

        override fun getAppliedDisplayFilter(): String = activeFilter

        override fun applyDisplayFilter(
            filter: String,
            expectedSessionHandle: Long
        ): DisplayFilterResult {
            applyCalls += expectedSessionHandle to filter
            if (handle == 0L || handle != expectedSessionHandle) {
                return DisplayFilterResult(false, 0, "Session changed")
            }
            val cancelledRemaining = cancelledApplies[filter]
            if (cancelledRemaining != null && cancelledRemaining > 0) {
                cancelledApplies[filter] = cancelledRemaining - 1
                return DisplayFilterResult(false, visibleCount, "Operation cancelled.")
            }
            val failedRemaining = failedApplies[filter]
            if (failedRemaining != null && failedRemaining > 0) {
                failedApplies[filter] = failedRemaining - 1
                return DisplayFilterResult(false, visibleCount, "Apply rejected")
            }
            if (temporaryFilterApplied && failNextRestoreOf == filter) {
                failNextRestoreOf = null
                return DisplayFilterResult(false, visibleCount, "Restore failed")
            }
            activeFilter = filter
            visibleCount = when (filter) {
                "udp" -> 4
                "tcp" -> 2
                "dns" -> 1
                else -> totalFrames
            }
            temporaryFilterApplied = filter == "tcp"
            return DisplayFilterResult(true, visibleCount)
        }

        override fun validateDisplayFilter(filter: String): Result<Unit> =
            if (filter in invalidFilters) Result.failure(IllegalArgumentException("invalid"))
            else Result.success(Unit)

        override fun cancelLongRunningOperations() = Unit

        override fun getPacketSummaries(start: Int, count: Int): List<PacketSummary> = emptyList()

        override fun getRawPacketSummaries(start: Int, count: Int): List<PacketSummary> = emptyList()

        override fun getFirstPacketTimestamp(): Double = 0.0

        override fun searchPacketFrames(mode: PacketSearchMode, query: String): List<Long> = emptyList()

        override fun getPacketDetails(frameNumber: Long): ProtocolNode? =
            ProtocolNode(label = "Packet $frameNumber")

        override fun getExpertInfoSummary(): ExpertInfoSummary {
            lastNativeReadThread = Thread.currentThread().name
            return ExpertInfoSummary()
        }

        override fun buildCaptureStatistics(bucketSeconds: Double): CaptureStatistics {
            lastNativeReadThread = Thread.currentThread().name
            return CaptureStatistics(packetCount = visibleCount)
        }

        override fun buildCommunicationAnalysis(): CommunicationAnalysis {
            lastNativeReadThread = Thread.currentThread().name
            communicationAnalysisCalls += 1
            return CommunicationAnalysis()
        }

        override fun followStream(frameNumber: Long, protocol: String): FollowStreamResult =
            FollowStreamResult(protocol = protocol, streamId = -1, records = emptyList())

        fun switchSession(newHandle: Long, file: File) {
            handle = newHandle
            activeFilter = ""
            visibleCount = totalFrames
            temporaryFilterApplied = false
            fileInfo = FileSessionInfo(
                displayName = file.name,
                sizeBytes = file.length(),
                fileType = "pcap",
                frameCount = totalFrames,
                localPath = file.absolutePath
            )
        }

        fun closeSession() {
            handle = 0L
            activeFilter = ""
            visibleCount = 0
            fileInfo = null
            temporaryFilterApplied = false
        }
    }
}
