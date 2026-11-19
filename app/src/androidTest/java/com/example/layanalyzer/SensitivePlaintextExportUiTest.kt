// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import androidx.activity.ComponentActivity
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.model.*
import com.example.layanalyzer.ui.components.HttpObjectsScreen
import com.example.layanalyzer.ui.components.TlsFollowScreen
import com.example.layanalyzer.ui.components.PacketBytesDialog
import com.example.layanalyzer.data.CaptureAnalysisRevision
import com.example.layanalyzer.viewmodel.PacketBytesViewerState
import com.example.layanalyzer.viewmodel.PacketDataSourceState
import com.example.layanalyzer.viewmodel.TlsFollowViewerState
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Synthetic UI states; exporting callbacks never write files or send data. */
@RunWith(AndroidJUnit4::class)
class SensitivePlaintextExportUiTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private fun label(id: Int, vararg args: Any) = compose.activity.getString(id, *args)

    @Test fun streamCancellationAndRepeatedExportsRequireFreshConsent() {
        var exports = 0
        val result = TlsFollowResult(true, TlsFollowScope.CompleteConnection, 1, true,
            listOf(TlsFollowRecord(1, TlsFollowDirection.Client, false, "synthetic".toByteArray())),
            false, false, 0, 1, null, null)
        compose.setContent { TlsFollowScreen(TlsFollowViewerState(1, result), ExportUiState(), {},
            { exports++ }, {}, {}) }
        compose.onNodeWithContentDescription(label(R.string.tls_follow_export)).performClick()
        compose.onNodeWithText(label(R.string.tls_plaintext_export_stream_scope)).assertIsDisplayed()
        compose.runOnIdle { assertEquals(0, exports) }
        compose.onNodeWithText(label(R.string.cancel)).performClick()
        compose.runOnIdle { assertEquals(0, exports) }
        compose.onNodeWithContentDescription(label(R.string.tls_follow_export)).performClick()
        compose.onNodeWithText(label(R.string.tls_plaintext_export_confirm)).performClick()
        compose.runOnIdle { assertEquals(1, exports) }
        compose.onNodeWithContentDescription(label(R.string.tls_follow_export)).performClick()
        compose.runOnIdle { assertEquals(1, exports) }
    }

    @Test fun objectSearchDoesNotNarrowTheScopeOfExportAllConsent() {
        var all = 0
        var single = 0
        val entries = listOf(HttpObjectEntry(1, 1, "example.test", "text/plain", "first.txt", 10),
            HttpObjectEntry(2, 2, "example.test", "text/plain", "second.txt", 10))
        compose.setContent { HttpObjectsScreen(HttpObjectsState(analyzed = true, objects = entries),
            ExportUiState(), {}, { single++ }, { all++ }, {}, {}) }
        compose.onNodeWithText(label(R.string.filter_http_objects)).performTextInput("first")
        compose.onNodeWithText(label(R.string.export_all)).performClick()
        compose.onNodeWithText(label(R.string.tls_plaintext_export_objects_scope, 2)).assertIsDisplayed()
        compose.runOnIdle { assertEquals(0, all) }
        compose.onNodeWithText(label(R.string.tls_plaintext_export_confirm)).performClick()
        compose.runOnIdle { assertEquals(1, all) }
        compose.onNodeWithContentDescription(label(R.string.export_http_object, "first.txt")).performClick()
        compose.onNodeWithText(label(R.string.tls_plaintext_export_object_scope, "first.txt")).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.cancel)).performClick()
        compose.runOnIdle { assertEquals(0, single) }
    }

    @Test fun decryptedByteSaveRequiresConsentAndSourceSwitchDropsPendingConfirmation() {
        val raw = PacketDataSourceDescriptor("raw", "Frame", PacketDataSourceKind.RawFrame, 3, 3, false)
        val decrypted = PacketDataSourceDescriptor("tls", "TLS", PacketDataSourceKind.DecryptedTls, 3, 3, false)
        val detail = PacketDetailSnapshot(1, ProtocolNode("synthetic"), PacketDataSnapshotRef("synthetic", 1, 1),
            listOf(raw, decrypted))
        val initial = PacketDataSourceState().open(CaptureAnalysisRevision(sessionHandle = 1,
            dissectionGeneration = 1), detail).switchSource("tls").copy(bytes = byteArrayOf(1, 2, 3), selection = 0..2)
        var state by mutableStateOf(initial)
        val viewer = PacketBytesViewerState(1, "synthetic", true)
        var saved = 0
        compose.setContent { PacketBytesDialog(viewer, state, byteArrayOf(), {}, {}, onSaved = { saved++ }) }
        compose.onNodeWithContentDescription(label(R.string.save)).performClick()
        compose.onNodeWithText(label(R.string.tls_plaintext_export_bytes_scope)).assertIsDisplayed()
        compose.onNodeWithText(label(R.string.cancel)).performClick()
        compose.runOnIdle { assertEquals(0, saved) }
        compose.onNodeWithContentDescription(label(R.string.save)).performClick()
        compose.runOnIdle { state = state.switchSource("raw").copy(bytes = byteArrayOf(4, 5, 6)) }
        compose.onNodeWithText(label(R.string.tls_plaintext_export_title)).assertDoesNotExist()
        compose.runOnIdle { assertEquals(0, saved) }
    }
}
