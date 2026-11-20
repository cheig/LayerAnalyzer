// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Context
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.SocksBudgetStats
import com.example.layanalyzer.capture.SocksSessionStats
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class ProcessResourceSamplerTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    /** Explicit host command only; no VPN creation or traffic. */
    @Test
    fun collectIdle() {
        val args = InstrumentationRegistry.getArguments()
        org.junit.Assume.assumeTrue("Explicit resourceRunId required", args.containsKey("resourceRunId"))
        val runId = requireNotNull(args.getString("resourceRunId"))
        val duration = (args.getString("resourceSeconds") ?: "15").toLong()
        require(duration in 1..3600)
        check(!LiveCaptureStore.state.value.isCapturing) { "CAPTURE_ALREADY_ACTIVE" }
        val file = File(context.filesDir, "socks-nio-resources/$runId.jsonl")
        ProcessResourceSampler(file, runId).use { sampler ->
            sampler.sample("idle_before")
            sampler.startPeriodic { "idle" }
            SystemClock.sleep(duration * 1000)
            sampler.sample("idle_after")
        }
        InstrumentationRegistry.getInstrumentation().sendStatus(0, android.os.Bundle().apply {
            putString("resourceOutput", "files/socks-nio-resources/$runId.jsonl")
        })
    }

    @Test
    fun metricsAndMissingSessionsAreExplicit() {
        val runId = UUID.randomUUID().toString().replace("-", "")
        val file = File(context.cacheDir, "resource-$runId.jsonl")
        try {
            ProcessResourceSampler(file, runId, sessions = { null }).use { sampler ->
                val row = sampler.sample("test")
                val process = row.getJSONObject("process")
                assertTrue(process.getInt("threads") > 0)
                assertTrue(process.getInt("fds") > 0)
                assertTrue(process.getLong("pssKiB") > 0)
                assertTrue(process.getLong("startTicks") > 0)
                assertTrue(process.getJSONObject("fdLimits").getLong("soft") > 0)
                assertTrue(row.isNull("socks"))
                assertTrue(row.getJSONObject("unavailable").has("socks"))
                assertTrue(process.isNull("cpuPercentOneCore"))
            }
            val rows = file.readLines().map(::JSONObject)
            assertEquals("end", rows.last().getString("type"))
            assertEquals(1, rows.last().getInt("samples"))
        } finally { file.delete() }
    }

    @Test
    fun serverIdentityAndPeakSurviveStopAndRestart() {
        val runId = UUID.randomUUID().toString().replace("-", "")
        val file = File(context.cacheDir, "resource-$runId.jsonl")
        var stats = SocksSessionStats(0, 1, 0, 0, "first", true,
            SocksBudgetStats(0, 2, 64), SocksBudgetStats(1, 7, 64), SocksBudgetStats(0, 0, 64), emptyMap())
        try {
            ProcessResourceSampler(file, runId, sessions = { stats }).use { sampler ->
                assertEquals(7, sampler.sample("active").getJSONObject("socks").getJSONObject("tcp").getInt("peak"))
                stats = stats.copy(running = false, tcp = SocksBudgetStats(0, 7, 64))
                assertFalse(sampler.sample("stopped").getJSONObject("socks").getBoolean("running"))
                stats = stats.copy(serverId = "second", running = true, tcp = SocksBudgetStats(0, 0, 64))
                assertEquals("second", sampler.sample("restarted").getJSONObject("socks").getString("serverId"))
            }
        } finally { file.delete() }
    }
}
