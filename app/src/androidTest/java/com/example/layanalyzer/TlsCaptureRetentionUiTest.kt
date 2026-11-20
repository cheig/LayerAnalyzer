// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.res.Configuration
import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.runtime.*
import androidx.compose.material3.*
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.text.TextLayoutResult
import androidx.lifecycle.ViewModelStore
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.data.*
import com.example.layanalyzer.model.*
import com.example.layanalyzer.ui.components.SavedCaptureOpenDialog
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import com.example.layanalyzer.viewmodel.PacketListViewModel
import java.io.File
import java.util.Locale
import java.util.UUID
import kotlinx.coroutines.Job
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

/** Production ViewModel open/delete/close paths, real native decryption, production summary.
 * The snackbar host reproduces PacketListScreen's openError binding without a full app menu.
 */
class TlsCaptureRetentionUiTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    @Test fun chineseLight() = walk("zh", false)
    @Test fun chineseDark() = walk("zh", true)
    @Test fun englishLight() = walk("en", false)
    @Test fun englishDark() = walk("en", true)

    private fun walk(language: String, dark: Boolean) {
        NativeTestSupport.awaitApplicationEngine()
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assertEquals(360, compose.activity.resources.configuration.screenWidthDp)
        assertEquals(1.5f, compose.activity.resources.configuration.fontScale)
        val original = Configuration(compose.activity.resources.configuration)
        val config = Configuration(original).apply { setLocale(Locale(language)) }
        @Suppress("DEPRECATION")
        compose.runOnUiThread { compose.activity.resources.updateConfiguration(config, compose.activity.resources.displayMetrics) }
        val localized = compose.activity.createConfigurationContext(config)
        val artifacts = CaptureArtifactRepository(context)
        val secrets = TlsSecretStore(context)
        val lifecycle = CaptureArtifactLifecycle(context)
        val id = "tls312-ui-${UUID.randomUUID()}"
        val directory = artifacts.captureDirectory(id).apply { mkdirs() }
        val originalPacket = File(directory, "packets.pcap")
        val repository = PacketRepository().apply { artifactLifecycle = lifecycle }
        // Keep the ViewModel's applicationContext lookup in the selected test
        // locale, without changing the device language or production preferences.
        val modelContext = object : android.content.ContextWrapper(localized) {
            override fun getApplicationContext(): android.content.Context = this
        }
        val model = PacketListViewModel(repository, CaptureSessionCoordinator(repository), modelContext)
        val models = ViewModelStore()
        compose.runOnUiThread { models.put("retention", model) }
        val snackbars = SnackbarHostState()
        compose.setContent {
            CompositionLocalProvider(LocalContext provides localized, LocalConfiguration provides config) {
                LayerAnalyzerTheme(darkTheme = dark) {
                    val info by model.savedCaptureOpenInfo.collectAsState()
                    val error by model.openError.collectAsState()
                    LaunchedEffect(error) { error?.let { snackbars.showSnackbar(it, duration = SnackbarDuration.Indefinite) } }
                    Scaffold(snackbarHost = { SnackbarHost(snackbars) }) { padding ->
                        Box(Modifier.padding(padding)) {
                            info?.let { SavedCaptureOpenDialog(it, model::dismissSavedCaptureOpenInfo) }
                        }
                    }
                }
            }
        }
        try {
            TlsPassiveFixture("tls12-h1").use { fixture ->
                val frames = fixture.file("pcap").inputStream().use { input ->
                    originalPacket.outputStream().use { TlsRawCaptureWriter.copy(input, it) }
                }
                val originalBytes = originalPacket.readBytes()
                val ref = fixture.file("keylog").inputStream().use {
                    secrets.importRecords(id, KeyLogParser.parse(it) as KeyLogParseResult.Success)
                }
                artifacts.commit(CaptureArtifactManifest(id,
                    segments = listOf(CaptureSegmentRef(originalPacket.name, 1, frames)),
                    retentionPolicy = CaptureRetentionPolicy.KeepCaptureTransientSecrets,
                    secretsPersistedSequence = ref.watermark.sequence,
                    tls = CaptureTlsAssets(enabled = true, secretsAssetId = ref.assetId, complete = true), complete = true))
                // The production recent entry stores the analysis path; individual
                // segments intentionally use the ordinary single-file open path.
                val recent = RecentCapture("TLS-312 synthetic capture", originalPacket.length(), artifacts.analysisFile(id).path, 0)
                fun open() {
                    compose.runOnUiThread { model.openRecentCapture(recent) }
                    await {
                        var finished = false
                        instrumentation.runOnMainSync {
                            val field = PacketListViewModel::class.java.getDeclaredField("openJob").apply { isAccessible = true }
                            finished = (field.get(model) as? Job)?.isCompleted == true
                        }
                        finished
                    }
                    assertNull(model.openError.value)
                    assertNotNull(model.savedCaptureOpenInfo.value)
                    assertTrue(repository.currentAnalysisRevision().ready)
                    assertTrue(repository.applyDecodeAsRule(DecodeAsRule("fixture", DecodeAsScope.Port,
                        DecodeAsTransport.TCP, "", "", null, fixture.port, "tls")).success)
                }
                open()
                fixture.assertBody(repository.currentSessionHandle(), true)
                val first = requireNotNull(model.savedCaptureOpenInfo.value)
                assertTrue(first.message.contains(localized.getString(R.string.saved_capture_open_transient_secrets)))
                readable(first.message)
                shot(language, dark, "01-transient-warning")
                compose.onNodeWithText(localized.getString(R.string.close)).performClick()
                compose.runOnUiThread { model.deleteRecentCapture(recent) }
                val inUse = localized.getString(R.string.error_close_before_delete)
                compose.waitUntil { model.openError.value == inUse }
                readable(inUse)
                shot(language, dark, "02-analysis-in-use")
                assertArrayEquals(originalBytes, originalPacket.readBytes())
                assertNotNull(secrets.currentAsset(id))
                compose.runOnUiThread { model.clearOpenError(); model.closeFile() }
                assertNull(secrets.currentAsset(id))
                assertFalse(File(context.noBackupFilesDir, "capture-secrets/$id").exists())
                assertArrayEquals(originalBytes, originalPacket.readBytes())
                open()
                fixture.assertBody(repository.currentSessionHandle(), false)
                val reopened = requireNotNull(model.savedCaptureOpenInfo.value)
                assertTrue(reopened.message.contains(localized.getString(R.string.saved_capture_open_no_secrets)))
                readable(reopened.message)
                shot(language, dark, "03-reopened-ciphertext")
                compose.runOnUiThread { model.dismissSavedCaptureOpenInfo(); model.closeFile() }
                // Real capture use registry, as held by the writer, also blocks the UI delete path.
                CaptureFileAccess.retain(directory).use {
                    compose.runOnUiThread { model.deleteRecentCapture(recent) }
                    compose.waitUntil { model.openError.value == inUse }
                    readable(inUse)
                    shot(language, dark, "04-capture-in-use")
                    assertTrue(originalPacket.exists())
                }
                repeat(2) {
                    val before = CaptureArtifactLifecycle.cleanupRevision.value
                    compose.runOnUiThread { model.clearOpenError(); model.deleteRecentCapture(recent) }
                    // Removing PCAP happens before the journal/lock transaction ends.
                    await { CaptureArtifactLifecycle.cleanupRevision.value >= before + 2 }
                    awaitIdle(directory)
                    assertFalse(originalPacket.exists())
                    assertTrue(lifecycle.cleanupEvents().single { it.captureId == id }.completed)
                }
                assertNull(model.openError.value)
            }
        } finally {
            compose.runOnUiThread { models.clear() }
            repository.closeFile()
            awaitIdle(directory)
            lifecycle.purge(id)
            @Suppress("DEPRECATION")
            compose.runOnUiThread { compose.activity.resources.updateConfiguration(original, compose.activity.resources.displayMetrics) }
        }
    }

    private fun readable(text: String) {
        val layouts = mutableListOf<TextLayoutResult>()
        compose.onNodeWithText(text, useUnmergedTree = true).assertIsDisplayed()
            .performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
        assertTrue(layouts.isNotEmpty())
        layouts.forEach { layout ->
            assertEquals(text.length, layout.getLineEnd(layout.lineCount - 1))
            assertFalse(layout.hasVisualOverflow)
            for (line in 0 until layout.lineCount) assertFalse(layout.isLineEllipsized(line))
        }
    }
    private fun shot(language: String, dark: Boolean, name: String) {
        compose.waitForIdle(); Thread.sleep(200)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val output = File(instrumentation.targetContext.getExternalFilesDir(null), "tls-312/screenshots").apply { mkdirs() }
        val bitmap = instrumentation.uiAutomation.takeScreenshot()
        File(output, "$language-${if (dark) "dark" else "light"}-$name.png").outputStream().use {
            assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it))
        }
        bitmap.recycle()
    }
    private fun await(test: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 15000
        while (System.currentTimeMillis() < deadline) { if (test()) return; Thread.sleep(50) }
        error("Timed out awaiting retention operation")
    }
    private fun awaitIdle(directory: File) = await {
        try { CaptureFileAccess.idle(listOf(directory)) {}; true }
        catch (error: TlsAssetException) {
            if (error.code != TlsAssetErrorCode.IN_USE) throw error
            false
        }
    }
}
