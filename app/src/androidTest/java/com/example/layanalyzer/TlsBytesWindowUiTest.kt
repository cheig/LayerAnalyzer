// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.ClipboardManager
import android.content.Context
import androidx.activity.ComponentActivity
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.text.TextLayoutResult
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.data.CaptureAnalysisRevision
import com.example.layanalyzer.model.PacketDataSnapshotRef
import com.example.layanalyzer.model.PacketDataSourceDescriptor
import com.example.layanalyzer.model.PacketDataSourceKind
import com.example.layanalyzer.model.PacketDetailSnapshot
import com.example.layanalyzer.model.ProtocolNode
import com.example.layanalyzer.ui.components.PacketBytesDialog
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import com.example.layanalyzer.viewmodel.PacketDataSourceState
import com.example.layanalyzer.viewmodel.PacketBytesViewerState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * TLS-307 U: production dialog on a real 360dp viewport. Synthetic source bytes/state exercise
 * rendering and clipboard behavior; real JNI decryption is covered by TlsBytesSelectionTest.
 */
@RunWith(AndroidJUnit4::class)
class TlsBytesWindowUiTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun lightTheme() = walkThrough(false)
    @Test fun darkTheme() = walkThrough(true)

    private fun walkThrough(dark: Boolean) {
        val configuration = compose.activity.resources.configuration
        assertEquals("Run on a real 360dp viewport", 360, configuration.screenWidthDp)
        val output = File(compose.activity.getExternalFilesDir(null),
            "tls-307/${if (dark) "dark" else "light"}-360dp").apply { mkdirs() }
        val body = ("TLS-307 synthetic body with enough text to cross the narrow viewport. " +
            "The final bytes must remain readable.").toByteArray()
        val raw = PacketDataSourceDescriptor("raw", "Frame", PacketDataSourceKind.RawFrame, 8, 8, false)
        val decrypted = PacketDataSourceDescriptor("source-1", "Decrypted TLS",
            PacketDataSourceKind.DecryptedTls, body.size.toLong(), body.size, false)
        val detail = PacketDetailSnapshot(16, ProtocolNode("http.file_data"),
            PacketDataSnapshotRef("ui-synthetic", 1, 16), listOf(raw, decrypted))
        val initial = PacketDataSourceState().open(CaptureAnalysisRevision(
            sessionHandle = 1, dissectionGeneration = 1), detail)
            .switchSource(decrypted.id).copy(bytes = body, selection = body.indices)
        var state by mutableStateOf(initial)
        var viewer by mutableStateOf(PacketBytesViewerState(16, "http.file_data", true))
        var copies = 0
        compose.setContent {
            LayerAnalyzerTheme(darkTheme = dark) {
                PacketBytesDialog(viewer, state, byteArrayOf(0x7f), {}, { id ->
                    state = state.switchSource(id).copy(bytes =
                        if (id == raw.id) ByteArray(8) { 0x16 } else body)
                }, onCopied = { copies++ })
            }
        }
        fun label(id: Int, vararg args: Any) = compose.activity.getString(id, *args)
        fun screenshot(name: String) {
            compose.waitForIdle()
            val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
            val bitmap = automation.takeScreenshot()
            File(output, "$name.png").outputStream().use {
                assertTrue(bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it))
            }
            bitmap.recycle()
        }
        fun sourceLabel(kind: Int) = label(R.string.bytes_source_label, label(kind))
        fun disabledActions() {
            compose.onNodeWithText(label(R.string.bytes_source_unavailable)).assertIsDisplayed()
            compose.onNodeWithContentDescription(label(R.string.copy)).assertIsNotEnabled()
            compose.onNodeWithContentDescription(label(R.string.save)).assertIsNotEnabled()
        }

        compose.onNodeWithText(sourceLabel(R.string.bytes_source_kind_decrypted_tls)).assertIsDisplayed()
        compose.onNodeWithText("ASCII").performClick()
        compose.onNodeWithText(String(body)).assertIsDisplayed()
        val layouts = mutableListOf<TextLayoutResult>()
        compose.onNodeWithText(String(body)).performSemanticsAction(SemanticsActions.GetTextLayoutResult) {
            it(layouts)
        }
        assertTrue("The complete long body must wrap", layouts.isNotEmpty())
        layouts.forEach { layout ->
            assertTrue(layout.lineCount > 1)
            assertEquals(body.size, layout.getLineEnd(layout.lineCount - 1))
            for (line in 0 until layout.lineCount) {
                assertTrue("Body text clipped horizontally", layout.getLineRight(line) <= layout.size.width + 1f)
                assertTrue("Body text clipped vertically", layout.getLineBottom(line) <= layout.size.height + 1f)
            }
        }
        compose.onNodeWithContentDescription(label(R.string.copy)).assertIsEnabled().performClick()
        compose.runOnIdle {
            val clipboard = compose.activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            assertEquals(String(body), clipboard.primaryClip!!.getItemAt(0).text.toString())
            assertEquals(1, copies)
        }
        screenshot("01-selected-source-and-copy")
        compose.onNodeWithText(label(R.string.bytes_source_kind_raw_frame)).performClick()
        compose.onNodeWithText(sourceLabel(R.string.bytes_source_kind_raw_frame)).assertIsDisplayed()
        compose.onNodeWithText(String(body)).assertDoesNotExist()
        compose.onNodeWithText("........").assertIsDisplayed()
        screenshot("02-raw-source")
        compose.onNodeWithText(label(R.string.bytes_source_kind_decrypted_tls)).performClick()
        compose.onNodeWithText(String(body)).assertIsDisplayed()

        // A retained source prefix must show both its actual available length and original length.
        compose.runOnIdle {
            state = initial.copy(detail = detail.copy(sources = listOf(raw,
                decrypted.copy(byteLength = 1000, truncated = true))))
        }
        compose.onNodeWithText(label(R.string.bytes_source_truncated, body.size, 1000L)).assertIsDisplayed()
        screenshot("03-truncated-source")

        // State after the ViewModel refreshes an evicted tree: no stale source selection/bytes.
        compose.runOnIdle { state = initial.copy(sourceId = null, bytes = byteArrayOf(),
            selection = null, errorCode = "STALE_GENERATION") }
        compose.onNodeWithText(label(R.string.bytes_source_stale)).assertIsDisplayed()
        disabledActions()
        screenshot("04-evicted-source")

        // A generated/missing-offset node may have a cached window, but must not copy that window.
        compose.runOnIdle {
            state = initial.clearSelection()
            viewer = PacketBytesViewerState(16, "generated / no offset", false)
        }
        disabledActions()
        screenshot("05-no-byte-range")

        // Switching frame clears old output immediately while the new request is outstanding.
        compose.runOnIdle {
            state = PacketDataSourceState().open(CaptureAnalysisRevision(
                sessionHandle = 1, dissectionGeneration = 1), detail.copy(frameNumber = 17,
                snapshot = PacketDataSnapshotRef("ui-next-frame", 1, 17))).beginRange(0, 8)
            viewer = PacketBytesViewerState(17, "next frame loading", true)
        }
        compose.onNodeWithText(String(body)).assertDoesNotExist()
        compose.onNodeWithContentDescription(label(R.string.copy)).assertIsNotEnabled()
        compose.onNodeWithContentDescription(label(R.string.save)).assertIsNotEnabled()
        screenshot("06-next-frame-loading")
        File(output, "profile.txt").writeText(
            "widthDp=${configuration.screenWidthDp}\nfontScale=${configuration.fontScale}\n" +
                "dark=$dark\nsyntheticSources=true\nclipboardMatches=true\n")
    }
}
