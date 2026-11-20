// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.capture.tls.TlsConnectionStore
import com.example.layanalyzer.capture.tls.TlsConnectionStoreLimits
import com.example.layanalyzer.model.TlsConnectionEvent
import com.example.layanalyzer.model.TlsConnectionPhase
import com.example.layanalyzer.model.TlsError
import com.example.layanalyzer.model.TlsErrorCode
import com.example.layanalyzer.ui.components.TlsConnectionPreviewSection
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import com.example.layanalyzer.viewmodel.TlsConnectionUiProjection
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * TLS-306 U acceptance: the production composable, in its production LazyColumn
 * container shape, on a device. Inputs are synthetic metadata, not TLS traffic.
 * Run at wm density 480 (1080px / 3 = 360dp), font_scale 1.0 and 1.5.
 * Screenshots supplement text-layout and interaction assertions; review them too.
 */
@RunWith(AndroidJUnit4::class)
class TlsConnectionPreviewUiTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun lightTheme() = walkThrough(dark = false)
    @Test fun darkTheme() = walkThrough(dark = true)

    @Test fun closureAndHistoryOverflowDoNotImplyCertificateRejection() {
        val store = TlsConnectionStore("tls-306-synthetic", TlsConnectionStoreLimits(maxEvents = 2))
        assertTrue(store.append(event(1, "closed", TlsConnectionPhase.DOWNSTREAM_HANDSHAKE)))
        assertTrue(store.append(event(2, "closed", TlsConnectionPhase.FAILED).copy(
            error = TlsError(TlsErrorCode.IO_ERROR), decisionReason = "downstream_connection_closed"
        )))
        assertTrue(store.append(event(3, "bypass", TlsConnectionPhase.PASSTHROUGH).copy(
            decisionReason = "handshake_capacity_exceeded"
        )))
        assertTrue(store.recordEngineStats("""{"success":true,"events":{"bytesToUpstream":0,"bytesToDownstream":0,"eventsDropped":0,"handshakeCapacityPassthrough":1}}"""))
        val snapshot = store.snapshot()
        compose.setContent {
            LayerAnalyzerTheme {
                Surface(Modifier.fillMaxSize()) {
                    LazyColumn(contentPadding = PaddingValues(16.dp)) {
                        item { TlsConnectionPreviewSection(snapshot, TlsConnectionUiProjection.summary(snapshot), {}) }
                    }
                }
            }
        }
        fun label(id: Int, vararg args: Any) = compose.activity.getString(id, *args)
        fun visible(text: String) { compose.onNodeWithText(text).performScrollTo().assertIsDisplayed() }
        visible(label(R.string.tls_connection_history_evicted, 1L))
        visible(label(R.string.tls_connection_handshake_capacity_bypass, 1L))
        assertFalse(TlsConnectionUiProjection.summary(snapshot).countersIncomplete)
        compose.onAllNodesWithText(label(R.string.tls_connection_expand))[1].performScrollTo().performClick()
        visible(label(R.string.tls_connection_error_downstream_closed))
        assertTrue(compose.onAllNodesWithText(label(R.string.tls_connection_error_downstream_rejected)).fetchSemanticsNodes().isEmpty())
        val output = File(compose.activity.getExternalFilesDir(null), "tls-failure-explanations").apply { mkdirs() }
        File(output, "closed-and-history.png").outputStream().use {
            assertTrue(compose.onRoot().captureToImage().asAndroidBitmap().compress(Bitmap.CompressFormat.PNG, 100, it))
        }
    }

    private fun walkThrough(dark: Boolean) {
        val configuration = compose.activity.resources.configuration
        assertEquals("Run on a 360dp device viewport", 360, configuration.screenWidthDp)
        val profile = "${configuration.locales[0].language}-${if (dark) "dark" else "light"}-360dp-font${configuration.fontScale}"
        val output = File(compose.activity.getExternalFilesDir(null), "tls-306/$profile").apply { mkdirs() }
        val store = TlsConnectionStore("tls-306-synthetic", TlsConnectionStoreLimits(maxEvents = 2))
        val relay = event(1, "saved", TlsConnectionPhase.RELAYING)
        assertTrue(store.append(relay))
        assertTrue(store.append(event(2, "saved", TlsConnectionPhase.CLOSED).copy(
            secretRecordsAccepted = 4, secretRecordsPersisted = 4, secretsComplete = true
        )))
        val rejected = event(3, "rejected", TlsConnectionPhase.FAILED).copy(
            error = TlsError(TlsErrorCode.DOWNSTREAM_TLS_REJECTED)
        )
        assertTrue(store.append(rejected))
        assertFalse(store.append(relay)) // Out-of-order event.
        assertFalse(store.append(rejected)) // Duplicate event.
        assertTrue(store.append(event(4, "bypass", TlsConnectionPhase.PASSTHROUGH).copy(
            decisionReason = "BYPASS_RULE", upstreamCertificateSha256 = null,
            downstreamTls = null, upstreamTls = null, alpn = null
        )))
        assertTrue(store.append(event(5, "incomplete", TlsConnectionPhase.RELAYING)))
        assertTrue(store.append(event(6, "incomplete", TlsConnectionPhase.CLOSED).copy(
            error = TlsError(TlsErrorCode.SECRETS_INCOMPLETE),
            secretRecordsAccepted = 4, secretRecordsPersisted = 2
        )))
        var snapshot by mutableStateOf(store.snapshot())
        var jumpCalls = 0
        compose.setContent {
            LayerAnalyzerTheme(darkTheme = dark) {
                Surface(Modifier.fillMaxSize()) {
                    LazyColumn(contentPadding = PaddingValues(16.dp)) {
                        item {
                            TlsConnectionPreviewSection(
                                snapshot, TlsConnectionUiProjection.summary(snapshot), { jumpCalls++ }
                            )
                        }
                    }
                }
            }
        }

        fun label(id: Int, vararg args: Any) = compose.activity.getString(id, *args)
        fun readable(text: String) {
            val node = compose.onNodeWithText(text).performScrollTo().assertIsDisplayed()
            val layouts = mutableListOf<TextLayoutResult>()
            node.performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
            assertTrue("No layout for $text", layouts.isNotEmpty())
            layouts.forEach { layout ->
                // Compose can report paragraph.width = max constraint even when
                // the Text node shrinks to its actual line width. Check rendered
                // line extents instead of hasVisualOverflow's empty paragraph area.
                assertFalse("Clipped height: $text", layout.didOverflowHeight)
                assertEquals(text.length, layout.getLineEnd(layout.lineCount - 1))
                for (line in 0 until layout.lineCount) {
                    assertFalse(layout.isLineEllipsized(line))
                    assertTrue("Clipped left: $text", layout.getLineLeft(line) >= -1f)
                    assertTrue("Clipped right: $text", layout.getLineRight(line) <= layout.size.width + 1f)
                    assertTrue("Clipped bottom: $text", layout.getLineBottom(line) <= layout.size.height + 1f)
                }
            }
        }
        fun screenshot(name: String) {
            File(output, "$name.png").outputStream().use {
                assertTrue(compose.onRoot().captureToImage().asAndroidBitmap().compress(Bitmap.CompressFormat.PNG, 100, it))
            }
        }
        fun expand(index: Int) {
            compose.onAllNodesWithText(label(R.string.tls_connection_expand))[index]
                .performScrollTo().performClick()
        }
        fun collapse() {
            compose.onNodeWithText(label(R.string.tls_connection_collapse)).performScrollTo().performClick()
        }
        fun disabledJump() {
            readable(label(R.string.tls_connection_frame_not_correlated))
            compose.onNodeWithText(label(R.string.tls_connection_jump))
                .performScrollTo().assertIsNotEnabled().performClick()
            compose.runOnIdle { assertEquals(0, jumpCalls) }
        }

        readable(label(R.string.tls_connection_summary_line_1, 2L, 1L, 0L))
        readable(label(R.string.tls_connection_summary_line_2, 1L, 1L, 1L))
        readable(label(R.string.tls_connection_decrypted_pending))
        readable(label(R.string.tls_connection_quic_untracked))
        readable(label(R.string.tls_connection_secrets_incomplete, 1L))
        readable(label(R.string.tls_connection_history_evicted, 4L))
        readable(label(R.string.tls_connection_counters_incomplete, 0L, 2L, 0L))
        screenshot("01-summary")

        expand(3)
        readable(label(R.string.tls_connection_sni, SNI))
        readable(label(R.string.tls_connection_downstream_tls, "TLS 1.3"))
        readable(label(R.string.tls_connection_upstream_tls, "TLS 1.2"))
        readable(label(R.string.tls_connection_alpn, "http/1.1"))
        screenshot("02-separated-handshakes")
        readable(label(R.string.tls_connection_upstream_cert, FINGERPRINT))
        readable(label(R.string.tls_connection_decision, REASON))
        screenshot("03-long-fields")
        readable(label(R.string.tls_connection_keys_saved, 4L))
        disabledJump()
        screenshot("04-saved-disabled-jump")
        // A publication must retain expansion and the final summary, not collapse
        // the row or manufacture a jump target when the snapshot object changes.
        compose.runOnIdle {
            store.close()
            snapshot = store.snapshot()
        }
        readable(label(R.string.tls_connection_keys_saved, 4L))
        collapse()

        expand(2)
        readable(label(R.string.tls_connection_keys_none))
        readable(label(R.string.tls_connection_error, "DOWNSTREAM_TLS_REJECTED"))
        readable(label(R.string.tls_connection_error_downstream_rejected))
        disabledJump()
        screenshot("05-rejected-no-keys")
        collapse()

        expand(1)
        readable(label(R.string.tls_connection_upstream_cert_unknown))
        readable(label(R.string.tls_connection_decision, "BYPASS_RULE"))
        readable(label(R.string.tls_connection_keys_none))
        disabledJump()
        screenshot("06-bypass")
        collapse()

        expand(0)
        readable(label(R.string.tls_connection_keys_incomplete, 2L, 4L))
        readable(label(R.string.tls_connection_error, "SECRETS_INCOMPLETE"))
        readable(label(R.string.tls_connection_error_secrets_incomplete))
        disabledJump()
        screenshot("07-incomplete")
        collapse()
        readable(label(R.string.tls_connection_summary_line_1, 2L, 1L, 0L))
        screenshot("08-final-summary")
        File(output, "profile.txt").writeText(
            "profile=$profile\nwidthDp=${configuration.screenWidthDp}\nfontScale=${configuration.fontScale}\n" +
                "syntheticMetadataOnly=true\nproxied=2 keysSaved=1 decrypted=0 bypassed=1 failed=1\n" +
                "eventsDropped=0 eventHistoryEvicted=4 eventsRejected=2\ntextOverflow=0 ellipsizedLines=0 jumpCalls=$jumpCalls\n"
        )
        store.close()
    }

    private fun event(sequence: Long, id: String, phase: TlsConnectionPhase) = TlsConnectionEvent(
        captureId = "tls-306-synthetic", connectionId = id, eventSequence = sequence,
        monotonicNanos = sequence * 1_000_000, wallTimeMillis = 1_792_195_200_000 + sequence,
        destinationIp = "2001:db8:1234:5678:abcd:ef01:2345:6789", destinationPort = 443,
        networkGeneration = 1, phase = phase, sni = SNI,
        downstreamTls = "TLS 1.3", upstreamTls = "TLS 1.2", alpn = "http/1.1",
        decisionReason = REASON, upstreamCertificateSha256 = FINGERPRINT
    )

    private companion object {
        const val SNI = "long-synthetic-connection-name.tls-306.example.invalid"
        const val REASON = "EXPLICIT_HOST_RULE_MATCH_SYNTHETIC_ACCEPTANCE_LONG_REASON"
        val FINGERPRINT = (0 until 32).joinToString(":") { "%02X".format(it) }
    }
}
