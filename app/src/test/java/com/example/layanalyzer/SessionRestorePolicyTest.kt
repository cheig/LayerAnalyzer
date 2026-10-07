package com.example.layanalyzer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionRestorePolicyTest {
    private val savedSession = RestorableSession(
        path = "/captures/last.pcap",
        displayName = "last.pcap",
        sizeBytes = 4096L
    )

    @Test
    fun validSavedSessionWaitsForUserConfirmation() {
        val decision = decideSessionStartup(savedSession, fileExists = true)

        assertEquals(SessionStartupDecision.AskToRestore(savedSession), decision)
    }

    @Test
    fun missingCaptureDoesNotPromptForRestore() {
        val decision = decideSessionStartup(savedSession, fileExists = false)

        assertTrue(decision is SessionStartupDecision.ContinueWithoutRestore)
    }

    @Test
    fun absentSavedSessionContinuesWithoutRestore() {
        val decision = decideSessionStartup(savedSession = null, fileExists = false)

        assertTrue(decision is SessionStartupDecision.ContinueWithoutRestore)
    }

    @Test
    fun freshLauncherActivityConfirmsAnAlreadyOpenSession() {
        assertTrue(
            shouldRequestActiveSessionConfirmation(
                isFreshActivityLaunch = true,
                hasExplicitOpenRequest = false,
                hasOpenSession = true
            )
        )
    }

    @Test
    fun recreationAndExplicitFileOpenDoNotPromptForCurrentSession() {
        assertEquals(
            false,
            shouldRequestActiveSessionConfirmation(
                isFreshActivityLaunch = false,
                hasExplicitOpenRequest = false,
                hasOpenSession = true
            )
        )
        assertEquals(
            false,
            shouldRequestActiveSessionConfirmation(
                isFreshActivityLaunch = true,
                hasExplicitOpenRequest = true,
                hasOpenSession = true
            )
        )
    }
}
