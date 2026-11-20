// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.graphics.Bitmap
import android.net.Uri
import android.provider.DocumentsContract
import android.view.accessibility.AccessibilityNodeInfo
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.ViewModelStore
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.data.*
import com.example.layanalyzer.model.*
import com.example.layanalyzer.ui.components.TlsCaptureExportDialog
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import com.example.layanalyzer.viewmodel.PacketListViewModel
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

/** Production ViewModel + real Keystore/JNI/content resolver; real DocumentsUI for user selection. */
class TlsCaptureSafTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val resolver get() = context.contentResolver
    private val authority = "com.layeranalyzer.tls311.test.documents"
    private val provider get() = Uri.parse("content://$authority")
    private fun doc(id: String) = DocumentsContract.buildDocumentUri(authority, id)
    private fun call(method: String) = resolver.call(provider, "tls311-$method", null, null)!!
    private fun main(block: () -> Unit) = instrumentation.runOnMainSync(block)
    private fun await(label: String, condition: () -> Boolean) {
        val until = System.nanoTime() + 30_000_000_000L
        while (!condition() && System.nanoTime() < until) Thread.sleep(40)
        assertTrue("Timed out: $label", condition())
    }

    @Test fun systemPickerCancelSaveImportAndRecentReopen() = withCapture { model, packets, fixture, ids ->
        var show by mutableStateOf(false)
        var destination: Uri? = null
        var returned = 0
        compose.setContent { LayerAnalyzerTheme {
            val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) {
                destination = it; returned++; model.saveCaptureExport(it)
            }
            if (show) TlsCaptureExportDialog(false, { kind, confirmed ->
                show = false
                check(model.prepareCaptureExport(kind, confirmed))
                save.launch("tls311-session.zip")
            }, { show = false })
            else TextButton(onClick = { show = true }) { Text("TLS-311 export") }
        } }
        fun begin() {
            compose.onNodeWithText("TLS-311 export").performClick()
            compose.onNodeWithText(context.getString(R.string.tls_capture_export_complete)).performScrollTo().performClick()
            compose.onNode(isToggleable()).performScrollTo().performClick()
            compose.onNodeWithText(context.getString(R.string.tls_capture_export_save)).performClick()
            await("DocumentsUI") { nodes().any { it.packageName?.contains("documentsui") == true } }
            clickNode { it.className == "android.widget.ImageButton" && it.contentDescription?.isNotBlank() == true }
            clickNode { it.text?.toString() == "TLS-311 fixtures" }
            await("fixture root save action") { nodes().any { it.viewIdResourceName == "android:id/button1" && it.isEnabled } }
        }
        begin()
        shot("saf-01-cancel")
        instrumentation.uiAutomation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK)
        await("cancel callback") { returned == 1 }
        assertNull(destination)
        assertFalse(model.exportState.value.isExporting)
        cleanWorkspace()
        begin()
        await("save action") { nodes().any { it.viewIdResourceName == "android:id/button1" && it.isEnabled } }
        shot("saf-02-test-root")
        clickNode { it.viewIdResourceName == "android:id/button1" && it.isEnabled }
        await("save complete") { returned == 2 && model.exportState.value.message != null && !model.exportState.value.isExporting }
        assertNull(model.exportState.value.error)
        val exportedUri = requireNotNull(destination)
        val exported = resolver.openInputStream(exportedUri)!!.use { it.readBytes() }
        assertTrue(exported.size > 1000)
        cleanWorkspace()
        val sourceAsset = model.savedCaptureOpenInfo.value!!.captureId
        main { model.importTlsCaptureBundle(exportedUri) }
        awaitOpen(model, packets)
        val importedId = model.savedCaptureOpenInfo.value!!.captureId
        ids += importedId
        assertNotEquals(sourceAsset, importedId)
        body(fixture, packets)
        val current = requireNotNull(model.currentFile.value)
        main { model.closeFile() }
        await("close") { packets.currentSessionHandle() == 0L }
        main { model.openRecentCapture(RecentCapture(current.displayName, current.sizeBytes, current.localPath, 0)) }
        awaitOpen(model, packets)
        body(fixture, packets)
        compose.onNodeWithText("TLS-311 export").assertIsDisplayed()
        assertTrue(DocumentsContract.deleteDocument(resolver, exportedUri))
        // A malformed URI import must surface a fixed error and allow the normal recent-open path afterwards.
        val bad = DocumentsContract.createDocument(resolver, doc("root"), "application/zip", "invalid.zip")!!
        resolver.openOutputStream(bad, "wt")!!.use { it.write(byteArrayOf(0, 1, 2)) }
        main { model.importTlsCaptureBundle(bad) }
        await("invalid import") { model.openProgress.value == null && model.openError.value != null }
        assertEquals(context.getString(R.string.tls_capture_import_failed), model.openError.value)
        cleanWorkspace()
        main { model.openRecentCapture(RecentCapture(current.displayName, current.sizeBytes, current.localPath, 0)) }
        awaitOpen(model, packets)
        body(fixture, packets)
        assertTrue(DocumentsContract.deleteDocument(resolver, bad))
    }

    @Test fun providerFailuresCancellationAndFileSwitchCleanPrivatePlaintext() = withCapture { model, packets, _, _ ->
        TlsPassiveFixture("tls13-h1").use { other ->
            for (name in listOf("fail-delete", "fail-truncate", "fail-all", "blocked-cancel", "blocked-switch")) {
                android.util.Log.i("TLS-311-SAF", "starting=$name")
                call("reset")
                val uri = DocumentsContract.createDocument(resolver, doc("root"), "application/zip", name)!!
                main {
                    model.clearExportState()
                    assertTrue(model.prepareCaptureExport(TlsCaptureExportKind.CompleteDecryptableSession, true))
                    model.saveCaptureExport(uri)
                }
                await("provider opened") { call("state").getInt("opened") > 0 }
                if (name.startsWith("blocked")) {
                    assertTrue(model.exportState.value.isExporting)
                    // The archive has already been built with actual exported keys before the target opens.
                    assertTrue(File(context.noBackupFilesDir, "tls-bundle-work").walkTopDown().any { it.name == "export.tmp" && it.length() > 0 })
                    if (name == "blocked-cancel") main { model.cancelCaptureExport() }
                    else main { model.openRecentCapture(RecentCapture("TLS-311 second fixture",
                        other.file("pcap").length(), other.file("pcap").path, 0)) }
                    call("release")
                }
                await("rollback $name") { !model.exportState.value.isExporting && model.exportState.value.error != null }
                android.util.Log.i("TLS-311-SAF", "finished=$name exporting=${model.exportState.value.isExporting} " +
                    "deleteAttempts=${call("state").getInt("deleted")}")
                cleanWorkspace()
                assertTrue(call("state").getInt("deleted") > 0)
                when (name) {
                    "fail-all" -> {
                        assertEquals(context.getString(R.string.tls_capture_export_destination_cleanup), model.exportState.value.error)
                        assertTrue(resolver.openInputStream(uri)!!.use { it.readBytes() }.isNotEmpty())
                    }
                    "fail-truncate" -> assertEquals(0, resolver.openInputStream(uri)!!.use { it.readBytes().size })
                    else -> assertTrue(resolver.query(uri, null, null, null, null)?.use { it.count == 0 } ?: true)
                }
            }
            await("new file after export cancellation") { openFinished(model) && model.openProgress.value == null &&
                model.currentFile.value?.localPath == other.file("pcap").path && packets.currentAnalysisRevision().ready }
            val handle = packets.currentSessionHandle()
            assertTrue(JSONObject(NativeEngine.applyDecodeAs(handle, "tcp.port", other.port, "tls")).getBoolean("success"))
            other.assertBody(handle, false)
            NativeEngine.resetDecodeAs(handle, "tcp.port", other.port)
            main { model.closeFile() }
            assertEquals(0L, packets.currentSessionHandle())
            // No active analysis lease is left after the final file switch.
            assertTrue(File(context.noBackupFilesDir, "tls-analysis-leases").listFiles().orEmpty().isEmpty())
        }
    }

    private fun withCapture(block: (PacketListViewModel, PacketRepository, TlsPassiveFixture, MutableSet<String>) -> Unit) {
        NativeTestSupport.awaitApplicationEngine()
        // The test APK grants access only to its own fixture provider; no system permission is bypassed.
        context.startActivity(android.content.Intent().setClassName(instrumentation.context.packageName,
            Tls311GrantActivity::class.java.name).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
        await("fixture provider grant") { runCatching { call("state") }.isSuccess }
        call("reset")
        val artifacts = CaptureArtifactRepository(context)
        val secrets = TlsSecretStore(context)
        val packets = PacketRepository()
        val model = PacketListViewModel(packets, CaptureSessionCoordinator(packets), context)
        val models = ViewModelStore()
        val id = "tls311-${UUID.randomUUID()}"
        val ids = mutableSetOf(id)
        main { models.put("tls311", model) }
        TlsPassiveFixture("tls12-h1").use { fixture ->
            try {
                val directory = artifacts.captureDirectory(id).apply { mkdirs() }
                fixture.file("pcap").copyTo(File(directory, "packets.pcap"))
                val frames = fixture.file("pcap").inputStream().use { TlsRawCaptureWriter.copy(it, ByteArrayOutputStream()) }
                val parsed = fixture.file("keylog").inputStream().use(KeyLogParser::parse) as KeyLogParseResult.Success
                val ref = secrets.importRecords(id, parsed)
                artifacts.commit(CaptureArtifactManifest(id, segments = listOf(CaptureSegmentRef("packets.pcap", 1, frames)),
                    secretsPersistedSequence = ref.watermark.sequence,
                    tls = CaptureTlsAssets(enabled = true, secretsAssetId = ref.assetId, complete = true), complete = true))
                val merged = artifacts.openForAnalysis(id) as CaptureAnalysisSource.Merged
                main { model.openRecentCapture(RecentCapture("TLS-311 public fixture", merged.analysisFile.length(), merged.analysisFile.path, 0)) }
                awaitOpen(model, packets)
                body(fixture, packets)
                block(model, packets, fixture, ids)
            } finally {
                call("release")
                main { model.closeFile(); models.clear() }
                packets.closeFile()
                ids.forEach { captureId ->
                    secrets.purgeCapture(captureId)
                    val directory = artifacts.captureDirectory(captureId)
                    check(directory.canonicalFile.parentFile == File(context.filesDir, "captures").canonicalFile)
                    directory.deleteRecursively()
                }
                call("reset")
            }
        }
    }
    private fun awaitOpen(model: PacketListViewModel, packets: PacketRepository) {
        await("open") { openFinished(model) && (model.openError.value != null || (model.openProgress.value == null &&
            model.currentFile.value != null && model.savedCaptureOpenInfo.value != null && packets.currentAnalysisRevision().ready)) }
        assertNull(model.openError.value)
        assertTrue(model.savedCaptureOpenInfo.value!!.decryptionComplete)
    }
    private fun openFinished(model: PacketListViewModel): Boolean {
        // The UI publishes file info before its retained-key transaction; wait for that transaction too.
        val field = PacketListViewModel::class.java.getDeclaredField("openJob").apply { isAccessible = true }
        return (field.get(model) as? kotlinx.coroutines.Job)?.isCompleted == true
    }
    private fun body(fixture: TlsPassiveFixture, packets: PacketRepository) {
        val handle = packets.currentSessionHandle()
        assertTrue(JSONObject(NativeEngine.applyDecodeAs(handle, "tcp.port", fixture.port, "tls")).getBoolean("success"))
        fixture.assertBody(handle, true)
        NativeEngine.resetDecodeAs(handle, "tcp.port", fixture.port)
    }
    private fun cleanWorkspace() {
        assertTrue(File(context.noBackupFilesDir, "tls-bundle-work").listFiles().orEmpty().isEmpty())
        // The currently open analysis legitimately owns one keylog; export must not leave another.
        assertTrue(File(context.noBackupFilesDir, "tls-analysis-leases").listFiles().orEmpty().size <= 1)
    }
    private fun nodes(): List<AccessibilityNodeInfo> {
        val result = mutableListOf<AccessibilityNodeInfo>()
        fun visit(node: AccessibilityNodeInfo) {
            result += node
            for (i in 0 until node.childCount) node.getChild(i)?.let(::visit)
        }
        instrumentation.uiAutomation.rootInActiveWindow?.let(::visit)
        return result
    }
    private fun clickNode(predicate: (AccessibilityNodeInfo) -> Boolean) {
        var clicked = false
        await("system control click") {
            if (!clicked) {
                // DocumentsUI replaces its root nodes during drawer/window transitions.
                var node = nodes().firstOrNull { it.isVisibleToUser && it.isEnabled && predicate(it) }
                while (node != null && !node.isClickable) node = node.parent
                clicked = node?.performAction(AccessibilityNodeInfo.ACTION_CLICK) == true
            }
            clicked
        }
    }
    private fun shot(name: String) {
        Thread.sleep(250)
        val output = File(context.getExternalFilesDir(null), "tls-311/screenshots").apply { mkdirs() }
        val bitmap = instrumentation.uiAutomation.takeScreenshot()
        File(output, "$name.png").outputStream().use { assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)) }
        bitmap.recycle()
    }
}
