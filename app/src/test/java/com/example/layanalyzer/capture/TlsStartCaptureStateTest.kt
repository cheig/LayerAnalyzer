// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import com.example.layanalyzer.capture.tls.TlsCaState
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * TLS-315: the start conditions, the notification's degradation vocabulary and the
 * "stop and start again" lifecycle rule — the three decisions the card asks the
 * product entry point to get right.
 *
 * Every case here is a pure decision (no device, no Keystore, no notification, no
 * Compose), which is what makes the two halves of acceptance 2 claimable on a host:
 * "no fake running state" is the [TlsStartGate] refusing before the service is
 * asked, and "the TLS-off flow adds no gate" is the same function returning Ready
 * for a disabled configuration no matter how broken the environment is.
 */
class TlsStartCaptureStateTest {

    private val enabledTls = TlsCaptureSettings(enabled = true)
    private val disabledTls = TlsCaptureSettings(enabled = false)

    private val healthyCa = TlsCaState.READY
    private val plentyOfSpace = 512L * 1024L * 1024L

    // --- TlsStartGate: the disabled flow has no gate at all (C03 1, acceptance 2) ---

    @Test
    fun aDisabledConfigurationStartsWithNoGateEvenWhenEverythingElseIsBroken() {
        val readiness = TlsStartGate.evaluate(
            tls = disabledTls,
            configurationValid = false,
            facts = TlsStartFacts(featureBuilt = false, caState = null, freeBytes = 0L)
        )
        assertEquals(TlsStartReadiness.Ready, readiness)
    }

    // --- TlsStartGate: each enabled refusal names one thing (step 1) ---

    @Test
    fun anEnabledConfigurationWithInvalidSettingsIsRefusedAsConfiguration() {
        val readiness = TlsStartGate.evaluate(
            tls = enabledTls,
            configurationValid = false,
            facts = TlsStartFacts(featureBuilt = true, caState = healthyCa, freeBytes = plentyOfSpace)
        )
        assertEquals(TlsStartReadiness.Blocked(TlsStartBlockReason.CONFIGURATION_INVALID), readiness)
    }

    @Test
    fun anEnabledConfigurationInABuildWithoutTheEngineIsRefusedAsUnavailable() {
        val readiness = TlsStartGate.evaluate(
            tls = enabledTls,
            configurationValid = true,
            facts = TlsStartFacts(featureBuilt = false, caState = healthyCa, freeBytes = plentyOfSpace)
        )
        assertEquals(TlsStartReadiness.Blocked(TlsStartBlockReason.FEATURE_UNAVAILABLE), readiness)
    }

    @Test
    fun anUnreadOrUnusableCaIsRefusedBeforeAnyCaptureIsMinted() {
        // null means "not read yet", which is deliberately not "installed": starting
        // anyway would mint a root no application has been asked to trust.
        val states = listOf(
            null,
            TlsCaState.MISSING,
            TlsCaState.EXPIRED,
            TlsCaState.NOT_YET_VALID,
            TlsCaState.KEY_UNAVAILABLE,
            TlsCaState.INVALID_FORMAT,
            TlsCaState.IO_ERROR
        )
        states.forEach { caState ->
            val readiness = TlsStartGate.evaluate(
                tls = enabledTls,
                configurationValid = true,
                facts = TlsStartFacts(featureBuilt = true, caState = caState, freeBytes = plentyOfSpace)
            )
            assertEquals("caState=$caState", TlsStartReadiness.Blocked(TlsStartBlockReason.CA_NOT_READY), readiness)
        }
    }

    @Test
    fun aReadableCaBelowTheStorageFloorIsRefusedAsStorage() {
        val readiness = TlsStartGate.evaluate(
            tls = enabledTls,
            configurationValid = true,
            facts = TlsStartFacts(
                featureBuilt = true,
                caState = healthyCa,
                freeBytes = TlsStartGate.MIN_FREE_BYTES - 1L
            )
        )
        assertEquals(TlsStartReadiness.Blocked(TlsStartBlockReason.STORAGE_LOW), readiness)
    }

    @Test
    fun aHealthyEnvironmentIsReadyAndTheStorageFloorIsInclusive() {
        val ready = TlsStartGate.evaluate(
            tls = enabledTls,
            configurationValid = true,
            facts = TlsStartFacts(featureBuilt = true, caState = healthyCa, freeBytes = plentyOfSpace)
        )
        assertEquals(TlsStartReadiness.Ready, ready)

        val atFloor = TlsStartGate.evaluate(
            tls = enabledTls,
            configurationValid = true,
            facts = TlsStartFacts(
                featureBuilt = true,
                caState = healthyCa,
                freeBytes = TlsStartGate.MIN_FREE_BYTES
            )
        )
        assertEquals(TlsStartReadiness.Ready, atFloor)
        assertTrue(TlsStartGate.MIN_FREE_BYTES > 0L)
    }

    // --- CaptureNotificationPlan: the notification never over-claims (step 3) ---

    @Test
    fun aRunThatDoesNotInterceptShowsNoTlsLine() {
        assertEquals(
            CaptureNotificationTlsState.NOT_INTERCEPTING,
            CaptureNotificationPlan.tlsState(
                enabled = false,
                status = null,
                secretsComplete = true,
                mitmSuspended = false
            )
        )
        // Even if the engine somehow reported a state, a run that was not asked to
        // intercept does not claim a TLS line.
        assertEquals(
            CaptureNotificationTlsState.NOT_INTERCEPTING,
            CaptureNotificationPlan.tlsState(
                enabled = false,
                status = TlsCaptureStatus.RUNNING,
                secretsComplete = true,
                mitmSuspended = false
            )
        )
    }

    @Test
    fun anInterceptingRunWhoseSinkIsHealthyReadsAsIntercepting() {
        assertEquals(
            CaptureNotificationTlsState.INTERCEPTING,
            CaptureNotificationPlan.tlsState(
                enabled = true,
                status = TlsCaptureStatus.RUNNING,
                secretsComplete = false,
                mitmSuspended = false
            )
        )
        // Accepted-but-not-yet-persisted records are normal mid-run and must not be
        // reported as a degradation.
        assertEquals(
            CaptureNotificationTlsState.INTERCEPTING,
            CaptureNotificationPlan.tlsState(
                enabled = true,
                status = TlsCaptureStatus.STARTING,
                secretsComplete = true,
                mitmSuspended = false
            )
        )
    }

    @Test
    fun aSuspendedSinkSaysNewConnectionsAreNotDecryptedAndEstablishedOnesContinue() {
        // This is the writer/degradation case the card names: failure != null or a
        // refused record suspends *new* interception while established connections
        // keep forwarding (design §8.2).
        assertEquals(
            CaptureNotificationTlsState.DEGRADED,
            CaptureNotificationPlan.tlsState(
                enabled = true,
                status = TlsCaptureStatus.RUNNING,
                secretsComplete = false,
                mitmSuspended = true
            )
        )
        assertEquals(
            CaptureNotificationTlsState.DEGRADED,
            CaptureNotificationPlan.tlsState(
                enabled = true,
                status = TlsCaptureStatus.PAUSED,
                secretsComplete = false,
                mitmSuspended = false
            )
        )
    }

    @Test
    fun aFinishedRunReportsInterceptingOnlyWhenItsSecretsAreComplete() {
        assertEquals(
            CaptureNotificationTlsState.INTERCEPTING,
            CaptureNotificationPlan.tlsState(
                enabled = true,
                status = TlsCaptureStatus.STOPPED,
                secretsComplete = true,
                mitmSuspended = false
            )
        )
        assertEquals(
            CaptureNotificationTlsState.DEGRADED,
            CaptureNotificationPlan.tlsState(
                enabled = true,
                status = TlsCaptureStatus.STOPPED,
                secretsComplete = false,
                mitmSuspended = false
            )
        )
    }

    @Test
    fun aFailedOrUnknownInterceptionIsNeverReportedAsWorking() {
        listOf(TlsCaptureStatus.FAILED, TlsCaptureStatus.UNSUPPORTED).forEach { status ->
            assertEquals(
                "status=$status",
                CaptureNotificationTlsState.FAILED,
                CaptureNotificationPlan.tlsState(
                    enabled = true,
                    status = status,
                    secretsComplete = true,
                    mitmSuspended = false
                )
            )
        }
        assertEquals(
            CaptureNotificationTlsState.FAILED,
            CaptureNotificationPlan.tlsState(
                enabled = true,
                status = null,
                secretsComplete = true,
                mitmSuspended = false
            )
        )
        assertEquals(
            CaptureNotificationTlsState.DEGRADED,
            CaptureNotificationPlan.tlsState(
                enabled = true,
                status = TlsCaptureStatus.UNKNOWN,
                secretsComplete = true,
                mitmSuspended = false
            )
        )
        assertEquals(
            CaptureNotificationTlsState.NOT_INTERCEPTING,
            CaptureNotificationPlan.tlsState(
                enabled = true,
                status = TlsCaptureStatus.DISABLED,
                secretsComplete = true,
                mitmSuspended = false
            )
        )
    }

    // --- TlsModeChangePolicy: stop and start again (step 4) ---

    @Test
    fun aLiveCaptureIsNeverReconfiguredInPlace() {
        // The same predicate disables the settings controls and refuses a second
        // start request, so the UI and the service cannot disagree about whether a
        // running capture is being changed.
        assertTrue(TlsModeChangePolicy.acceptsNewRun(captureRunning = false))
        assertFalse(TlsModeChangePolicy.acceptsNewRun(captureRunning = true))
    }
}
