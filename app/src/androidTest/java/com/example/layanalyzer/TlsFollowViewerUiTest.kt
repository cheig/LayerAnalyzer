// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.ClipboardManager
import android.content.Context
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.text.TextLayoutResult
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.data.TlsFollowParser
import com.example.layanalyzer.model.*
import com.example.layanalyzer.ui.components.PacketContextMenu
import com.example.layanalyzer.ui.components.TlsFollowScreen
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import com.example.layanalyzer.viewmodel.TlsFollowViewerState
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Real JNI preview in production composables; explicitly synthetic states cover rare UI banners. */
@RunWith(AndroidJUnit4::class)
class TlsFollowViewerUiTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun lightTheme() = walkThrough(false)
    @Test fun darkTheme() = walkThrough(true)

    private fun walkThrough(dark: Boolean) {
        NativeTestSupport.awaitApplicationEngine()
        val configuration = compose.activity.resources.configuration
        assertEquals("Run on a real 360dp viewport", 360, configuration.screenWidthDp)
        val output = File(compose.activity.getExternalFilesDir(null),
            "tls-308/${if (dark) "dark" else "light"}-360dp").apply { mkdirs() }
        val initial = TlsPassiveFixture("tls12-h1").use { fixture ->
            val handle = fixture.open()
            try {
                val generation = JSONObject(NativeEngine.configureTlsSecrets(handle,
                    fixture.file("keylog").path, 1)).getLong("dissectionGeneration")
                TlsFollowParser.parse(NativeEngine.followTlsStream(handle, 0, generation,
                    TLS_FOLLOW_PREVIEW_LIMIT), generation, TLS_FOLLOW_PREVIEW_LIMIT)
            } finally { fixture.closeCapture(handle) }
        }
        assertTrue(initial.success)
        var viewer by mutableStateOf(TlsFollowViewerState(1, initial))
        var exporting by mutableStateOf(ExportUiState())
        var menu by mutableStateOf(true)
        var action by mutableStateOf(PacketTlsFollowAction.fromResult(initial))
        var exports = 0
        var cancellations = 0
        fun label(id: Int, vararg args: Any) = compose.activity.getString(id, *args)
        compose.setContent {
            LayerAnalyzerTheme(darkTheme = dark) {
                Box(Modifier.fillMaxSize()) {
                    if (menu) {
                        PacketContextMenu(PacketContextActionsState(frameNumber = 1,
                            followFilters = PacketFollowFilters(tcpStream = "tcp.stream == 0",
                                udpStream = "udp.stream == 0"), tlsFollow = action),
                            false, {}, {}, {}, { menu = false })
                    } else {
                        TlsFollowScreen(viewer, exporting, { menu = true }, {
                            exports++
                            exporting = ExportUiState(isExporting = true)
                        }, {
                            cancellations++
                            exporting = ExportUiState(message = label(R.string.tls_follow_export_cancelled))
                        }, {})
                    }
                }
            }
        }
        fun screenshot(name: String) {
            compose.waitForIdle()
            val bitmap = InstrumentationRegistry.getInstrumentation().uiAutomation.takeScreenshot()
            File(output, "$name.png").outputStream().use {
                assertTrue(bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it))
            }
            bitmap.recycle()
        }
        fun chip(text: String) = compose.onNodeWithText(text).performScrollTo().performClick()
        fun readable(text: String) {
            val layouts = mutableListOf<TextLayoutResult>()
            compose.onNodeWithText(text).assertIsDisplayed()
                .performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
            assertTrue(layouts.isNotEmpty())
            layouts.forEach { layout ->
                assertEquals(text.length, layout.getLineEnd(layout.lineCount - 1))
                for (line in 0 until layout.lineCount) {
                    assertFalse(layout.isLineEllipsized(line))
                    assertTrue(layout.getLineRight(line) <= layout.size.width + 1f)
                    assertTrue(layout.getLineBottom(line) <= layout.size.height + 1f)
                }
            }
        }

        compose.onNodeWithText(label(R.string.follow_tls_stream)).assertIsEnabled().performClick()
        readable(label(R.string.tls_follow_scope))
        readable(label(R.string.tls_follow_byte_stream_note))
        screenshot("01-real-preview")
        chip(label(R.string.stream_client))
        val client = initial.records.single { it.direction == TlsFollowDirection.Client }
        readable(String(client.bytes))
        compose.onNodeWithContentDescription(label(R.string.copy)).performClick()
        compose.runOnIdle {
            val clipboard = compose.activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            assertEquals("#${client.frameNumber} client\n${String(client.bytes)}",
                clipboard.primaryClip!!.getItemAt(0).text.toString())
        }
        chip("ASCII")
        val ascii = String(client.bytes).map { if (it.code in 32..126) it else '.' }.joinToString("")
        readable(ascii)
        screenshot("02-ascii-and-copy")
        chip("Hex")
        readable(client.bytes.joinToString(" ") { "%02X".format(it.toInt() and 255) })
        screenshot("03-hex")
        chip("UTF-8")
        compose.onNodeWithText(label(R.string.search_stream)).performTextInput("no-such-synthetic-record")
        compose.onNodeWithContentDescription(label(R.string.copy)).assertIsNotEnabled()
        compose.onNodeWithText(label(R.string.search_stream)).performTextClearance()
        InstrumentationRegistry.getInstrumentation().uiAutomation.performGlobalAction(
            android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK)
        compose.waitForIdle()

        // Export button/cancel callback plumbing only. Real file cleanup is TlsFollowExportTest.
        compose.onNodeWithContentDescription(label(R.string.tls_follow_export)).performClick()
        compose.runOnIdle { assertEquals(0, exports) }
        compose.onNodeWithText(label(R.string.tls_plaintext_export_confirm)).performClick()
        compose.onNodeWithText(label(R.string.tls_follow_exporting)).assertIsDisplayed()
        screenshot("04-exporting")
        compose.onNodeWithText(label(R.string.cancel)).performClick()
        compose.onNodeWithText(label(R.string.tls_follow_export_cancelled)).assertIsDisplayed()
        compose.runOnIdle { assertEquals(1, exports); assertEquals(1, cancellations) }
        screenshot("05-cancelled")

        // Synthetic unknown direction/truncation state; never claimed to be a 1 MiB fixture.
        compose.runOnIdle {
            exporting = ExportUiState()
            viewer = TlsFollowViewerState(2, initial.copy(directionKnown = false, incomplete = true,
                truncated = true, records = listOf(TlsFollowRecord(2, TlsFollowDirection.Unknown,
                    null, "Synthetic unknown-direction preview".toByteArray()))))
        }
        readable(label(R.string.tls_follow_direction_unknown))
        readable(label(R.string.tls_follow_incomplete))
        readable(label(R.string.tls_follow_truncated, TLS_FOLLOW_PREVIEW_LIMIT))
        screenshot("06-unknown-incomplete-truncated")
        chip(label(R.string.stream_client))
        compose.onNodeWithContentDescription(label(R.string.copy)).assertIsNotEnabled()

        for ((index, pair) in listOf(
            TlsFollowUnavailableReason.SecretsNotConfigured to R.string.tls_follow_prompt_no_secrets,
            TlsFollowUnavailableReason.HandshakeIncomplete to R.string.tls_follow_prompt_handshake_incomplete
        ).withIndex()) {
            compose.runOnIdle {
                viewer = TlsFollowViewerState(3L + index, initial.copy(success = false,
                    records = emptyList(), incomplete = true, errorCode = TlsErrorCode.NOT_READY,
                    unavailableReason = pair.first))
            }
            readable(label(pair.second))
            compose.onNodeWithContentDescription(label(R.string.copy)).assertIsNotEnabled()
            compose.onNodeWithContentDescription(label(R.string.tls_follow_export)).assertIsNotEnabled()
            screenshot("0${7 + index}-${pair.first.wireName.lowercase()}")
        }
        compose.runOnIdle {
            menu = true
            action = PacketTlsFollowAction(errorCode = TlsErrorCode.STALE_GENERATION)
        }
        compose.onNodeWithText(label(R.string.tls_follow_prompt_stale)).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.follow_tls_stream)).assertIsNotEnabled()
        compose.onNodeWithText(label(R.string.follow_tcp_filter)).assertIsEnabled()
        compose.onNodeWithText(label(R.string.follow_udp_filter)).assertIsEnabled()
        screenshot("09-stale-context-menu")
        File(output, "profile.txt").writeText("widthDp=${configuration.screenWidthDp}\n" +
            "fontScale=${configuration.fontScale}\ndark=$dark\npreview=real-JNI-tls12-h1\n" +
            "exceptionStates=synthetic\nexportCallbacks=test-host\nclipboardMatches=true\n")
    }
}
