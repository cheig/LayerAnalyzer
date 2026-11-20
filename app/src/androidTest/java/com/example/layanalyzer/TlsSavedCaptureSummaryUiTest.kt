// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.runtime.*
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.text.TextLayoutResult
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.data.CaptureOpenScope
import com.example.layanalyzer.data.SavedCaptureOpenInfo
import com.example.layanalyzer.model.CaptureMode
import com.example.layanalyzer.model.PacketVantage
import com.example.layanalyzer.ui.components.SavedCaptureOpenDialog
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Render the actual ViewModel summaries recorded by the immediately preceding open suite. */
@RunWith(AndroidJUnit4::class)
class TlsSavedCaptureSummaryUiTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun realOpenSummariesRemainReadableInBothThemesAt360dp() {
        assertEquals(360, compose.activity.resources.configuration.screenWidthDp)
        val root = File(compose.activity.getExternalFilesDir(null), "tls-310")
        val files = File(root, "summaries").listFiles()!!.filter { it.extension == "json" }.sortedBy { it.name }
        assertTrue(files.any { it.name.startsWith("SingleSegment-") })
        assertTrue(files.any { it.name.startsWith("LegacySingleFile-") })
        assertTrue(files.any { it.name.contains("SECRETS_ABSENT") })
        assertTrue(files.any { it.name.contains("MISSING_SEGMENT") })
        var dark by mutableStateOf(false)
        var shown by mutableStateOf<SavedCaptureOpenInfo?>(null)
        compose.setContent { LayerAnalyzerTheme(darkTheme = dark) {
            shown?.let { SavedCaptureOpenDialog(it) { shown = null } }
        } }
        for ((index, file) in files.withIndex()) {
            val json = JSONObject(file.readText())
            val info = SavedCaptureOpenInfo("test-summary", json.getString("message"),
                CaptureOpenScope.valueOf(json.getString("scope")), json.getLong("frames"), json.getLong("drops"),
                json.getBoolean("decryptionComplete"), json.getBoolean("contextIncomplete"), CaptureMode.VpnCapture,
                PacketVantage.valueOf(json.getString("vantage")), emptyList())
            for (theme in listOf("light", "dark")) {
                compose.runOnIdle { dark = theme == "dark"; shown = info }
                compose.waitForIdle()
                Thread.sleep(300) // Android window animation is outside Compose's idling clock.
                val screenshot = InstrumentationRegistry.getInstrumentation().uiAutomation.takeScreenshot()
                File(root, "summary-${index + 1}-$theme-360dp.png").outputStream().use {
                    assertTrue(screenshot.compress(Bitmap.CompressFormat.PNG, 100, it))
                }
                screenshot.recycle()
                val layouts = mutableListOf<TextLayoutResult>()
                compose.onNodeWithText(info.message).assertIsDisplayed()
                    .performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
                assertTrue(layouts.isNotEmpty())
                layouts.forEach { layout ->
                    assertEquals(info.message.length, layout.getLineEnd(layout.lineCount - 1))
                    for (line in 0 until layout.lineCount) {
                        assertFalse(layout.isLineEllipsized(line))
                        assertTrue("${file.name}: line $line exceeds width", layout.getLineRight(line) <= layout.size.width + 1f)
                        assertTrue("${file.name}: line $line exceeds height", layout.getLineBottom(line) <= layout.size.height + 1f)
                    }
                }
                val vantage = compose.activity.getString(if (info.vantage == PacketVantage.TunInterface)
                    R.string.saved_capture_open_vantage_tun else R.string.saved_capture_open_vantage_proxy)
                if (info.scope == CaptureOpenScope.LegacySingleFile) compose.onNodeWithText(vantage).assertDoesNotExist()
                else compose.onNodeWithText(vantage).assertIsDisplayed()
                compose.onNodeWithText(compose.activity.getString(R.string.close)).performClick()
                compose.onNodeWithText(info.message).assertDoesNotExist()
            }
        }
    }
}
