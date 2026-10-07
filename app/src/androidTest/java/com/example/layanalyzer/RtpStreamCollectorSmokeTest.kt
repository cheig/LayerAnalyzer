// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.content.Context
import android.net.ConnectivityManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.json.JSONObject
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * RTP1-NAT-03「`rtp` tap 收集器 `RtpStreamCollector`」的临时冒烟测试。
 *
 * NAT-03 只交付原生层的收集器（`RtpStreamCollector` + `dissect_frame_with_taps`），
 * 它还没有自己的 JNI 入口 —— `scanRtpStreams`（RTP1-NAT-04）才负责把收集结果序列化
 * 出来。因此这里通过已经冻结的 `NativeEngine.scanRtpStreams` 驱动一次
 * `dissect_frame_with_taps` 遍历，断言 `sip_g711a_bidirectional.pcap` 收集到 2 条流
 * （双向各一条）。**如果在 NAT-04 接通后这里拿到 0 条，就是 `dissect_frame_with_taps`
 * 没接对**（见 C9）。
 *
 * 注意：当前 `scanRtpStreams` 仍是 RTP1-ARCH-01 的占位实现（返回空 streams），
 * 所以这个断言只有在 NAT-04 落地后才会真正通过；本卡只要求它能编译
 * （`:app:assembleDebugAndroidTest`），NAT-04 会补齐正式断言。
 */
@RunWith(AndroidJUnit4::class)
class RtpStreamCollectorSmokeTest {

    @Test(timeout = 30_000)
    fun bidirectionalCaptureYieldsTwoStreams() {
        val session = NativeEngine.openFile(captureFile.absolutePath, null)
        assertNotEquals(
            "openFile failed: ${NativeEngine.getLastError()}",
            0L,
            session
        )
        try {
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
            val streams = result.optJSONArray("streams")
            assertNotNull("scanRtpStreams result is missing the streams array", streams)
            assertEquals(
                "The rtp tap must collect one stream per direction",
                2,
                streams!!.length()
            )
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    companion object {
        private lateinit var appContext: Context
        private lateinit var captureFile: File

        @JvmStatic
        @BeforeClass
        fun initializeEngine() {
            appContext = ApplicationProvider.getApplicationContext()
            copyAssetFolder(appContext, "wireshark-data", File(appContext.filesDir, "wireshark-data"))
            captureFile = copyAssetFile(
                appContext,
                "rtp/sip_g711a_bidirectional.pcap",
                File(appContext.cacheDir, "rtp-sip-g711a-bidirectional.pcap")
            )

            val connectivityManager = appContext.getSystemService(ConnectivityManager::class.java)
            if (connectivityManager != null) NativeEngine.initCaresAndroid(connectivityManager)

            assertTrue(
                "Native engine initialization failed",
                NativeEngine.initEngine(appContext.filesDir.absolutePath)
            )
        }

        @JvmStatic
        @AfterClass
        fun cleanupEngine() {
            NativeEngine.cleanup()
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
