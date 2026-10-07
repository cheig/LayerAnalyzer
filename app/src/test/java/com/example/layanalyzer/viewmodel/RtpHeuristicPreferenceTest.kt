// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.model.AnalyzerPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [RtpHeuristicPreferenceOps] 的纯 JVM 单测（RTP1-KT-03）。
 *
 * `PacketListViewModel` 需要 `Context` 才能构造，而本项目没有 Robolectric，
 * 所以这里直接覆盖它在更新链路上用到的两个决策点，以及这些决策触发的失效
 * 副作用。协调器用 `Dispatchers.Unconfined` 注入，因此 bump 是同步可断言的。
 *
 * 真正的 SharedPreferences 往返断言需要 `Context`，本测试栈做不到（见报告
 * 的「未执行项」）。
 */
class RtpHeuristicPreferenceTest {

    @Test
    fun `the rtp heuristic preference defaults to off and keeps its persisted key`() {
        assertFalse(AnalyzerPreferences().rtpHeuristicEnabled)
        assertEquals("analyzer_preferences", RtpHeuristicPreferenceOps.PREFERENCE_FILE)
        assertEquals("rtpHeuristicEnabled", RtpHeuristicPreferenceOps.PREFERENCE_KEY)
    }

    @Test
    fun `flipping the preference bumps the analysis config version`() = runBlocking {
        val coordinator = coordinator()
        val before = coordinator.state.value.analysisConfigVersion
        val current = AnalyzerPreferences()
        val next = current.copy(rtpHeuristicEnabled = true)

        // 镜像 updatePreferences 里的守卫写法：changed 为真才 bump。
        if (RtpHeuristicPreferenceOps.changed(current, next)) {
            coordinator.bumpAnalysisConfigVersion()
        }

        assertEquals(before + 1, coordinator.state.value.analysisConfigVersion)
    }

    @Test
    fun `an unchanged preference does not bump the analysis config version`() = runBlocking {
        val coordinator = coordinator()
        val before = coordinator.state.value.analysisConfigVersion

        val enabled = AnalyzerPreferences(rtpHeuristicEnabled = true)
        val stillEnabled = enabled.copy(rtpHeuristicEnabled = true)
        assertFalse(RtpHeuristicPreferenceOps.changed(enabled, stillEnabled))
        if (RtpHeuristicPreferenceOps.changed(enabled, stillEnabled)) {
            coordinator.bumpAnalysisConfigVersion()
        }

        val disabled = AnalyzerPreferences(rtpHeuristicEnabled = false)
        val stillDisabled = disabled.copy(rtpHeuristicEnabled = false)
        assertFalse(RtpHeuristicPreferenceOps.changed(disabled, stillDisabled))
        if (RtpHeuristicPreferenceOps.changed(disabled, stillDisabled)) {
            coordinator.bumpAnalysisConfigVersion()
        }

        assertEquals(before, coordinator.state.value.analysisConfigVersion)
    }

    @Test
    fun `a native rejection rolls the preference back to the previous value`() {
        val previous = AnalyzerPreferences()
        val next = previous.copy(rtpHeuristicEnabled = true)

        val rolledBack = RtpHeuristicPreferenceOps.resolve(previous, next, "rtp heuristics unavailable")
        assertEquals(previous, rolledBack)
        assertFalse(rolledBack.rtpHeuristicEnabled)

        val accepted = RtpHeuristicPreferenceOps.resolve(previous, next, "")
        assertEquals(next, accepted)
        assertTrue(accepted.rtpHeuristicEnabled)
        // 回滚/接受只影响 rtpHeuristicEnabled，其它字段保持不动。
        assertEquals(previous.timeDisplayFormat, accepted.timeDisplayFormat)
        assertEquals(previous.nameResolutionEnabled, accepted.nameResolutionEnabled)
        assertEquals(previous.colorRulesEnabled, accepted.colorRulesEnabled)
        assertEquals(previous.defaultTreeExpansionDepth, accepted.defaultTreeExpansionDepth)
    }

    // ---- helpers ----------------------------------------------------------

    /** 没有打开任何会话的协调器：只用来驱动 analysisConfigVersion 的 bump。 */
    private fun coordinator(): CaptureSessionCoordinator =
        CaptureSessionCoordinator(
            dataSource = AgentToolTestHarness.FakeSource(FRAME_COUNT),
            fingerprintDispatcher = Dispatchers.Unconfined,
            nativeDispatcher = Dispatchers.Unconfined
        )

    private companion object {
        const val FRAME_COUNT = 10
    }
}
