package com.example.layanalyzer

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * RTP1-NAT-05「启发式开关」的仪器测试。
 *
 * [NativeEngine.setRtpHeuristicEnabled] 打开/关闭四个 `rtp_*` 启发式
 * （`rtp_udp`/`rtp_stun`/`rtp_classicstun`/`rtp_rtsp`）。夹具
 * `rtp_no_signal.pcap` 里没有任何静态/Decode As 依据，只有在启发式开启时
 * 才会被识别成 RTP，因此它是这条开关最直接的观测点：
 *
 * 1. 关闭（默认）时扫描 → 0 条流；
 * 2. `setRtpHeuristicEnabled(true)` → `isRtpHeuristicEnabled()==true`
 *    且重扫 → `streams.size() > 0`；
 * 3. `setRtpHeuristicEnabled(false)` → 重扫 → 又变回 0 条。
 *
 * 开关是进程级状态，所以三步必须在同一个用例里按顺序执行；[restoreHeuristic]
 * 在每个用例后把它复位为 `false`，避免影响其它测试。
 */
@RunWith(AndroidJUnit4::class)
class RtpHeuristicToggleTest {

    @Test(timeout = 60_000)
    fun heuristicToggleControlsRtpDiscovery() {
        val session = NativeEngine.openFile(captureFile.absolutePath, null)
        assertNotEquals(
            "openFile failed: ${NativeEngine.getLastError()}",
            0L,
            session
        )
        try {
            // 1. 默认关闭：rtp_no_signal.pcap 不应被启发式猜成 RTP。
            val disabledFirst = scan(session)
            assertFalse(
                "scanRtpStreams must report heuristicEnabled=false by default",
                disabledFirst.optBoolean("heuristicEnabled", true)
            )
            assertEquals(
                "heuristic-disabled scan must not guess RTP in rtp_no_signal.pcap",
                0,
                streamsOf(disabledFirst).length()
            )

            // 2. 打开启发式：开关生效，重扫后应能发现流。
            val enableResult = JSONObject(NativeEngine.setRtpHeuristicEnabled(true))
            assertEquals(
                "setRtpHeuristicEnabled reported an error: " +
                    enableResult.optString("error"),
                "",
                enableResult.optString("error")
            )
            assertTrue(
                "setRtpHeuristicEnabled must echo enabled=true",
                enableResult.optBoolean("enabled", false)
            )
            assertEquals(
                "all four rtp heuristics must be registered: " +
                    enableResult.optJSONArray("failed"),
                0,
                enableResult.optJSONArray("failed")?.length() ?: 0
            )
            assertTrue(
                "isRtpHeuristicEnabled must report true after enabling",
                NativeEngine.isRtpHeuristicEnabled()
            )

            val enabledScan = scan(session)
            assertTrue(
                "scanRtpStreams must report heuristicEnabled=true after enabling",
                enabledScan.optBoolean("heuristicEnabled", false)
            )
            assertTrue(
                "heuristic-enabled scan must discover at least one stream " +
                    "in rtp_no_signal.pcap",
                streamsOf(enabledScan).length() > 0
            )

            // 3. 关闭启发式：重扫应变回 0 条。
            val disableResult = JSONObject(NativeEngine.setRtpHeuristicEnabled(false))
            assertEquals(
                "setRtpHeuristicEnabled reported an error: " +
                    disableResult.optString("error"),
                "",
                disableResult.optString("error")
            )
            assertFalse(
                "isRtpHeuristicEnabled must report false after disabling",
                NativeEngine.isRtpHeuristicEnabled()
            )

            val disabledSecond = scan(session)
            assertFalse(
                "scanRtpStreams must report heuristicEnabled=false after disabling",
                disabledSecond.optBoolean("heuristicEnabled", true)
            )
            assertEquals(
                "heuristic-disabled scan must return zero streams again",
                0,
                streamsOf(disabledSecond).length()
            )
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    /** Runs one scan and asserts it completed without an error. */
    private fun scan(session: Long): JSONObject {
        val result = JSONObject(
            NativeEngine.scanRtpStreams(
                session,
                "{\"limitToDisplayFilter\":false}",
                null
            )
        )
        assertEquals(
            "scanRtpStreams reported an error: ${result.optString("error")}",
            "",
            result.optString("error")
        )
        return result
    }

    private fun streamsOf(result: JSONObject) = requireNotNull(
        result.optJSONArray("streams")
    ) { "scanRtpStreams result is missing the streams array" }

    /** Keeps the process-wide toggle off for the tests that follow. */
    @After
    fun restoreHeuristic() {
        NativeEngine.setRtpHeuristicEnabled(false)
    }

    companion object {
        private lateinit var appContext: Context
        private lateinit var testContext: Context
        private lateinit var captureFile: File

        @JvmStatic
        @BeforeClass
        fun initializeEngine() {
            appContext = ApplicationProvider.getApplicationContext()
            testContext = InstrumentationRegistry.getInstrumentation().context
            copyAssetFolder(appContext, "wireshark-data", File(appContext.filesDir, "wireshark-data"))
            captureFile = copyAssetFile(
                testContext,
                "rtp/rtp_no_signal.pcap",
                File(appContext.cacheDir, "rtp-no-signal.pcap")
            )

            val application = appContext as LayerAnalyzerApplication

            var engineState = runBlocking {
                withTimeout(30_000) {
                    application.engineState.first {
                        it is EngineState.Ready ||
                            it is EngineState.Failed ||
                            it is EngineState.AwaitingSessionRestore
                    }
                }
            }
            if (engineState is EngineState.AwaitingSessionRestore) {
                application.declineSessionRestore()
                engineState = runBlocking {
                    withTimeout(30_000) {
                        application.engineState.first {
                            it is EngineState.Ready || it is EngineState.Failed
                        }
                    }
                }
            }
            assertTrue(
                (engineState as? EngineState.Failed)?.message
                    ?: "Native engine did not initialize.",
                engineState is EngineState.Ready
            )

        }

        private fun copyAssetFolder(context: Context, assetPath: String, targetDir: File) {
            targetDir.mkdirs()
            val children = context.assets.list(assetPath).orEmpty()
            if (children.isEmpty()) {
                copyAssetFile(context, assetPath, targetDir)
                return
            }

            for (child in children) {
                val childAssetPath = "$assetPath/$child"
                val grandChildren = context.assets.list(childAssetPath).orEmpty()
                if (grandChildren.isEmpty()) {
                    copyAssetFile(context, childAssetPath, File(targetDir, child))
                } else {
                    copyAssetFolder(context, childAssetPath, File(targetDir, child))
                }
            }
        }

        private fun copyAssetFile(context: Context, assetPath: String, targetFile: File): File {
            targetFile.parentFile?.mkdirs()
            context.assets.open(assetPath).use { input ->
                targetFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            return targetFile
        }
    }
}
