// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertTrue

/** Application owns the process-wide Wireshark engine, including during instrumentation. */
internal object NativeTestSupport {
    fun awaitApplicationEngine(): LayerAnalyzerApplication {
        val application = ApplicationProvider.getApplicationContext<LayerAnalyzerApplication>()
        val state = runBlocking {
            withTimeout(30_000) {
                val initial = application.engineState.first {
                    it is EngineState.Ready || it is EngineState.Failed ||
                        it is EngineState.AwaitingSessionRestore
                }
                if (initial is EngineState.AwaitingSessionRestore) {
                    application.declineSessionRestore()
                    application.engineState.first { it is EngineState.Ready || it is EngineState.Failed }
                } else {
                    initial
                }
            }
        }
        assertTrue(
            (state as? EngineState.Failed)?.message ?: "Native engine did not initialize.",
            state is EngineState.Ready
        )
        return application
    }
}
