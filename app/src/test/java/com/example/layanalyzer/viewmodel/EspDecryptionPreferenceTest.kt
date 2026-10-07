package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.model.AnalyzerPreferences
import com.example.layanalyzer.model.EspDecryptionMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [EspDecryptionPreferenceOps] 的纯 JVM 单测。
 *
 * 与 [RtpHeuristicPreferenceTest] 同构：`PacketListViewModel` 需要 `Context`
 * 才能构造，而本项目没有 Robolectric，所以这里覆盖持久化键名、取值解析，以及
 * 更新链路上的两个决策点——包括它们触发的分析失效副作用。协调器用
 * `Dispatchers.Unconfined` 注入，因此 bump 是同步可断言的。
 *
 * 真正的 SharedPreferences 往返断言与原生探测（`setEspDecryptionMode`）都需要
 * `Context` / JNI，本测试栈做不到。
 */
class EspDecryptionPreferenceTest {

    @Test
    fun `the esp decryption preference defaults to probing and keeps its persisted key`() {
        assertEquals(EspDecryptionMode.Probe, AnalyzerPreferences().espDecryptionMode)
        assertEquals(EspDecryptionMode.Probe, EspDecryptionPreferenceOps.DEFAULT_MODE)
        assertEquals("analyzer_preferences", EspDecryptionPreferenceOps.PREFERENCE_FILE)
        assertEquals("espDecryptionMode", EspDecryptionPreferenceOps.PREFERENCE_KEY)
    }

    @Test
    fun `a stored mode round-trips and anything unrecognised falls back to probing`() {
        EspDecryptionMode.values().forEach { mode ->
            assertEquals(mode, EspDecryptionPreferenceOps.parse(mode.name))
        }
        // 缺失（首次启动）与陈旧/损坏的值都必须回落到默认策略。
        assertEquals(EspDecryptionMode.Probe, EspDecryptionPreferenceOps.parse(null))
        assertEquals(EspDecryptionMode.Probe, EspDecryptionPreferenceOps.parse(""))
        assertEquals(EspDecryptionMode.Probe, EspDecryptionPreferenceOps.parse("probe"))
        assertEquals(EspDecryptionMode.Probe, EspDecryptionPreferenceOps.parse("PROBE"))
        assertEquals(EspDecryptionMode.Probe, EspDecryptionPreferenceOps.parse("nonsense"))
    }

    @Test
    fun `changing the mode bumps the analysis config version`() = runBlocking {
        val coordinator = coordinator()
        val before = coordinator.state.value.analysisConfigVersion
        val current = AnalyzerPreferences()
        val next = current.copy(espDecryptionMode = EspDecryptionMode.Off)

        // 镜像 updatePreferences 里的守卫写法：changed 为真才 bump。
        if (EspDecryptionPreferenceOps.changed(current, next)) {
            coordinator.bumpAnalysisConfigVersion()
        }

        assertEquals(before + 1, coordinator.state.value.analysisConfigVersion)
    }

    @Test
    fun `an unchanged mode does not bump the analysis config version`() = runBlocking {
        val coordinator = coordinator()
        val before = coordinator.state.value.analysisConfigVersion

        val current = AnalyzerPreferences(espDecryptionMode = EspDecryptionMode.All)
        val same = current.copy(espDecryptionMode = EspDecryptionMode.All)
        assertFalse(EspDecryptionPreferenceOps.changed(current, same))
        if (EspDecryptionPreferenceOps.changed(current, same)) {
            coordinator.bumpAnalysisConfigVersion()
        }

        assertEquals(before, coordinator.state.value.analysisConfigVersion)
    }

    @Test
    fun `a different mode counts as a change`() {
        // 三个取值两两之间的切换都要被判为变化，否则 UI 选了也不生效。
        EspDecryptionMode.values().forEach { from ->
            EspDecryptionMode.values().forEach { to ->
                val changed = EspDecryptionPreferenceOps.changed(
                    AnalyzerPreferences(espDecryptionMode = from),
                    AnalyzerPreferences(espDecryptionMode = to)
                )
                assertEquals(from != to, changed)
            }
        }
    }

    @Test
    fun `a native rejection rolls the preference back to the previous value`() {
        val previous = AnalyzerPreferences(espDecryptionMode = EspDecryptionMode.Probe)
        val next = previous.copy(espDecryptionMode = EspDecryptionMode.All)

        val rolledBack = EspDecryptionPreferenceOps.resolve(previous, next, "esp unavailable")
        assertEquals(previous, rolledBack)
        assertEquals(EspDecryptionMode.Probe, rolledBack.espDecryptionMode)

        val accepted = EspDecryptionPreferenceOps.resolve(previous, next, "")
        assertEquals(next, accepted)
        assertEquals(EspDecryptionMode.All, accepted.espDecryptionMode)
        // 回滚/接受只影响 espDecryptionMode，其它字段保持不动。
        assertEquals(previous.timeDisplayFormat, accepted.timeDisplayFormat)
        assertEquals(previous.nameResolutionEnabled, accepted.nameResolutionEnabled)
        assertEquals(previous.colorRulesEnabled, accepted.colorRulesEnabled)
        assertEquals(previous.defaultTreeExpansionDepth, accepted.defaultTreeExpansionDepth)
        assertEquals(previous.rtpHeuristicEnabled, accepted.rtpHeuristicEnabled)
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
