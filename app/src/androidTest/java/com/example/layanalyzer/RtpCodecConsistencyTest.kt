// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpRepository
import com.example.layanalyzer.model.RtpCodecCatalog
import com.example.layanalyzer.model.RtpCodecCapabilities
import com.example.layanalyzer.model.RtpCodecRoute
import com.example.layanalyzer.model.RtpCodecUnavailableReason
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * RTP4-KT-05：原生编码能力与 Kotlin 目录的一致性（仪器测试）。
 *
 * 为什么必须是**仪器测试**：判据的两半分别住在原生层与 Kotlin 层。
 * `NativeEngine.getRtpCodecCapabilities()` 是本构建的事实（哪些编码真的能解码，
 * `LAYANALYZER_ENABLE_G729` / `LAYANALYZER_ENABLE_ILBC` 两个开关也在里面），
 * 而 `RtpCodecCatalog` 是 UI 的候选表。JVM 单测里没有 JNI，问不到原生那一半，
 * 只能靠这里把两边对上 —— 卡片 §2.6 点名的就是这个理由。
 *
 * 断言的是**包含关系**，不是相等：
 *
 *  - 原生 `audio` ⊆ Kotlin 目录 —— 原生说能解的，目录里必须查得到（否则 UI 里
 *    根本没有这个选项，用户没法把某个 PT 映射过去）。
 *  - Kotlin 里 `route != UNSUPPORTED` 的条目 —— 要么在原生 `audio` 里，要么本构建
 *    明确说了它编不进来（`unavailableReason` 非空）。默认构建里 iLBC 就是后一类
 *    （`LAYANALYZER_ENABLE_ILBC` 默认 OFF），所以这条不能写成「一律在原生列表里」，
 *    否则红的是默认构建本身。反过来，一个既不在原生列表里、`unavailableReason`
 *    又答不出来的条目就是真的漂移（例如 AMR 走了 MediaCodec 却忘了进原生表），
 *    这条断言会抓住它。
 *  - `video` 与 `audio` 不相交（H264 / H265 是反例），保证上面两条不是靠
 *    「两张表其实是一张」蒙对的。
 *  - `g729` / `ilbc` 两个布尔与 `audio` 的成员关系一致（同源，不得漂移）。
 *
 * 引擎初始化照抄 `RtpMediaCodecRenderTest` 的 `@BeforeClass`：这个端点本身不需要
 * 会话（进程级、无 sessionPtr），但 `LayerAnalyzerApplication` 要先跑到 Ready，
 * `PacketRepository` 才是一个可用的对象。
 */
@RunWith(AndroidJUnit4::class)
class RtpCodecConsistencyTest {

    /** 每个 id 都要能在目录里查到（原生 ⊆ Kotlin）。 */
    @Test(timeout = 120_000)
    fun nativeAudioListIsCoveredByTheKotlinCatalog() {
        val capabilities = capabilities()
        assertTrue("native audio list is empty", capabilities.audio.isNotEmpty())
        capabilities.audio.forEach { id ->
            assertNotNull(
                "native audio id is missing from RtpCodecCatalog.entries: $id",
                RtpCodecCatalog.byId(id)
            )
        }
    }

    /**
     * 目录里 `route != UNSUPPORTED` 的条目，原生必须真的解得了 —— 除非本构建
     * 明确说了它编不进来（`unavailableReason` 非空）。默认构建的 iLBC 就是后一类。
     */
    @Test(timeout = 120_000)
    fun everyRoutedKotlinEntryIsInTheNativeAudioList() {
        val capabilities = capabilities()
        val routed = RtpCodecCatalog.entries.filter { it.route != RtpCodecRoute.UNSUPPORTED }
        assertTrue("no routable entry in the catalog", routed.isNotEmpty())
        routed.forEach { entry ->
            assertTrue(
                "catalog entry is routable but neither this build's native audio list " +
                    "nor the build-switch reason accounts for it: ${entry.id}; " +
                    "native audio = ${capabilities.audio}",
                capabilities.hasAudio(entry.id) ||
                    RtpCodecCatalog.unavailableReason(entry.id, capabilities) != null
            )
        }
    }

    /** `g729` / `ilbc` 两个布尔必须与 `audio` 的成员关系一致（同源，不得漂移）。 */
    @Test(timeout = 120_000)
    fun buildSwitchesAgreeWithTheAudioList() {
        val capabilities = capabilities()
        assertEquals(
            "g729=${capabilities.g729} but \"g729\" in audio=${capabilities.hasAudio("g729")}",
            capabilities.g729,
            capabilities.hasAudio("g729")
        )
        assertEquals(
            "ilbc=${capabilities.ilbc} but \"iLBC\" in audio=${capabilities.hasAudio("iLBC")}",
            capabilities.ilbc,
            capabilities.hasAudio("iLBC")
        )
    }

    /**
     * `audio` 必须**恰好**等于「无条件清单 + 两个开关分别在构建里时各自那一个 id」。
     *
     * 这条把两个开关钉死：`-PlayanalyzerEnableG729=false` 的构建里 `g729` 为 false，
     * 于是 expected 里没有 `g729`；如果原生列表那时还留着它，这条断言就会红。它是
     * BLD-02 验收 2 在端点这一层的证据，而且在三种构建组合下都成立（不是给某一种
     * 构建写死的）。
     */
    @Test(timeout = 120_000)
    fun theAudioListIsExactlyTheUnconditionalListPlusTheBuildSwitches() {
        val capabilities = capabilities()
        val expected = UNCONDITIONAL_AUDIO_CODECS +
            (if (capabilities.g729) setOf("g729") else emptySet()) +
            (if (capabilities.ilbc) setOf("iLBC") else emptySet())
        assertEquals(expected, capabilities.audio)
    }

    /** 反例：视频编码不得出现在 `audio` 里，并且确实在 `video` 里。 */
    @Test(timeout = 120_000)
    fun videoCodecsAreNotAudioCodecs() {
        val capabilities = capabilities()
        listOf("H264", "H265").forEach { id ->
            assertFalse("$id must not be in the native audio list", capabilities.hasAudio(id))
            assertTrue("$id must be in the native video list", capabilities.video.contains(id))
        }
        // 目录里的那两个条目也必须是 VIDEO 语义（route == UNSUPPORTED）：它们可选，
        // 但只是用于统计，不应该被当成能解码的。
        listOf("H264", "H265").forEach { id ->
            assertEquals(
                RtpCodecRoute.UNSUPPORTED,
                RtpCodecCatalog.byId(id)?.route
            )
        }
    }

    /**
     * 置灰判定：本构建没有的编码必须给出原因，本构建有的必须没有原因。
     *
     * 这是 `unavailableReason()` 与原生 `g729` / `ilbc` 的对接点 —— 对话框里置灰的
     * 那一条，和原生 `rtp_decodability_reason()` 的「此构建未包含 X」说的是同一件事。
     */
    @Test(timeout = 120_000)
    fun unavailableReasonsFollowTheBuildSwitches() {
        val capabilities = capabilities()
        val g729Reason: RtpCodecUnavailableReason? =
            if (capabilities.g729) null else RtpCodecUnavailableReason.G729_NOT_IN_BUILD
        val ilbcReason: RtpCodecUnavailableReason? =
            if (capabilities.ilbc) null else RtpCodecUnavailableReason.ILBC_NOT_IN_BUILD
        assertEquals(g729Reason, RtpCodecCatalog.unavailableReason("g729", capabilities))
        assertEquals(ilbcReason, RtpCodecCatalog.unavailableReason("iLBC", capabilities))
        // fail-open：拿不到原生回答时一条都不置灰（卡片 §2.5）。
        RtpCodecCatalog.entries.forEach { entry ->
            assertEquals(
                null,
                RtpCodecCatalog.unavailableReason(entry.id, RtpCodecCapabilities.UNKNOWN)
            )
        }
    }

    /** 端点的信封字段：`schemaVersion` / `error`，与 RTP 的其他端点同一约定。 */
    @Test(timeout = 120_000)
    fun capabilitiesEndpointCarriesTheStandardEnvelope() {
        val root = JSONObject(NativeEngine.getRtpCodecCapabilities())
        assertEquals(1, root.optInt("schemaVersion", 0))
        assertEquals("", root.optString("error", "missing"))
        assertTrue(root.has("g729"))
        assertTrue(root.has("ilbc"))
    }

    private fun capabilities(): RtpCodecCapabilities =
        RtpRepository(PacketRepository()).codecCapabilities()

    companion object {
        /**
         * `kSupportedAudioCodecs`（`core/RtpCodecNames.h`）里**不依赖构建开关**的
         * 那一段，逐字照抄 RTP4-KT-05 的清单。
         */
        private val UNCONDITIONAL_AUDIO_CODECS = setOf(
            "g711A", "g711U", "L16", "g722",
            "G726-16", "G726-24", "G726-32", "G726-40",
            "AAL2-G726-16", "AAL2-G726-24", "AAL2-G726-32", "AAL2-G726-40",
            "AMR", "AMR-WB", "opus"
        )

        private lateinit var appContext: Context

        @BeforeClass
        fun initializeEngine() {
            appContext = ApplicationProvider.getApplicationContext()
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
            copyAssetFolder(
                appContext,
                "wireshark-data",
                File(appContext.filesDir, "wireshark-data")
            )
        }

        private fun copyAssetFolder(
            context: Context,
            assetPath: String,
            targetDir: File
        ) {
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
                    copyAssetFile(
                        context,
                        childAssetPath,
                        File(targetDir, child)
                    )
                } else {
                    copyAssetFolder(
                        context,
                        childAssetPath,
                        File(targetDir, child)
                    )
                }
            }
        }

        private fun copyAssetFile(
            context: Context,
            assetPath: String,
            targetFile: File
        ): File {
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
