// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.os.PowerManager

/**
 * Reads live device resources for the AI-25 local-model pre-flight.
 *
 * This is the only Android-aware part of the local-model path, which is what
 * keeps [LocalAiModelClient]'s policy (path containment, refusal, capability
 * degradation) testable on the JVM.
 */
class AndroidDeviceResourceProbe(context: Context) : DeviceResourceProbe {
    // Hold the application context: this probe is owned by a client that can
    // outlive the Activity that happened to create it.
    private val appContext: Context = context.applicationContext

    override fun availableRamMb(): Long {
        val activityManager = appContext.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
            ?: return 0L
        val info = ActivityManager.MemoryInfo()
        activityManager.getMemoryInfo(info)
        return info.availMem / BYTES_PER_MIB
    }

    override fun thermalStatus(): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return 0
        val powerManager = appContext.getSystemService(Context.POWER_SERVICE) as? PowerManager
            ?: return 0
        return powerManager.currentThermalStatus
    }

    private companion object {
        const val BYTES_PER_MIB = 1024L * 1024L
    }
}
