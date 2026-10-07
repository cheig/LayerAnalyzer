// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

data class RestorableSession(
    val path: String,
    val displayName: String,
    val sizeBytes: Long
)

sealed interface SessionStartupDecision {
    data object ContinueWithoutRestore : SessionStartupDecision
    data class AskToRestore(val session: RestorableSession) : SessionStartupDecision
}

fun decideSessionStartup(
    savedSession: RestorableSession?,
    fileExists: Boolean
): SessionStartupDecision {
    return if (savedSession != null && fileExists) {
        SessionStartupDecision.AskToRestore(savedSession)
    } else {
        SessionStartupDecision.ContinueWithoutRestore
    }
}

fun shouldRequestActiveSessionConfirmation(
    isFreshActivityLaunch: Boolean,
    hasExplicitOpenRequest: Boolean,
    hasOpenSession: Boolean
): Boolean {
    return isFreshActivityLaunch && !hasExplicitOpenRequest && hasOpenSession
}
