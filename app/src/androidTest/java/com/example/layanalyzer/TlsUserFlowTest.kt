// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.app.Notification
import android.app.NotificationManager
import android.content.*
import android.graphics.Bitmap
import android.net.*
import android.view.accessibility.AccessibilityNodeInfo
import androidx.activity.ComponentActivity
import androidx.compose.runtime.*
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.text.TextLayoutResult
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModelStore
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.*
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.data.*
import com.example.layanalyzer.model.*
import com.example.layanalyzer.ui.components.LiveCaptureScreen
import com.example.layanalyzer.ui.components.SavedCaptureOpenDialog
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import com.example.layanalyzer.viewmodel.PacketListViewModel
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.*
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.UUID
import javax.net.ssl.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.*
import org.junit.Assert.*
import org.junit.rules.TestName

/**
 * TLS-315: production screen -> ViewModel -> VPN -> automatic saved analysis.
 * Requires TLS ON / probe OFF, 360dp, VPN consent, tls315Host/Path/Body (base64).
 * The synthetic target trusts only a UUID test CA; upstream verification remains
 * the platform default. Low storage replaces only the free-space read.
 * Existing settings/CA are preserved; only owned test assets are deleted.
 */
class TlsUserFlowTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    @get:Rule val testName = TestName()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val connectivity get() = context.getSystemService(ConnectivityManager::class.java)
    private val args get() = InstrumentationRegistry.getArguments()
    private val host get() = requireNotNull(args.getString("tls315Host"))
    private val request get(): ByteArray {
        val path = requireNotNull(args.getString("tls315Path"))
        require(path.startsWith('/') && path.none { it == '\r' || it == '\n' })
        return "GET $path HTTP/1.1\r\nHost: $host\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".toByteArray()
    }
    private val expected get() = android.util.Base64.decode(requireNotNull(args.getString("tls315Body")), 0)
    private val output get() = File(context.getExternalFilesDir(null), "tls-315/${testName.methodName}").apply { mkdirs() }
    private val id = UUID.randomUUID().toString()
    private val alias = "layeranalyzer.test.tls315.$id"
    private lateinit var caRoot: File
    private lateinit var ca: TlsCertificateManager
    private lateinit var packets: PacketRepository
    private lateinit var model: PacketListViewModel
    private val models = ViewModelStore()
    private val captures = mutableSetOf<String>()
    private var previousSettings: String? = null
    private var savedPreferences = emptyMap<String, Map<String, *>>()
    private var freeBytes = Long.MAX_VALUE
    private var sentStarts = 0
    private val stateObserver = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
    @Volatile private var observedRunning = false
    private var dark by mutableStateOf(false)

    @Before fun prepare() {
        NativeTestSupport.awaitApplicationEngine()
        assertTrue(BuildConfig.TLS_ENABLED)
        assertFalse(BuildConfig.TLS_PROBE_ENABLED)
        assertEquals(360, compose.activity.resources.configuration.screenWidthDp)
        assertFalse("Do not interrupt an existing capture", LiveCaptureStore.state.value.isCapturing)
        assertFalse("Do not replace another VPN", isVpn())
        previousSettings = prefs().getString("settings", null)
        savedPreferences = listOf("recent_captures", "active_session").associateWith { name ->
            context.getSharedPreferences(name, Context.MODE_PRIVATE).all.toMap()
        }
        caRoot = File(context.noBackupFilesDir, "tls-315-$id").apply { mkdirs() }
        ca = TlsCertificateManager(caRoot, AndroidTlsWrappingKeyProvider(alias))
        TlsCaManagerHolder.installForTest { ca }
        LiveCaptureStore.clearError()
        stateObserver.launch { LiveCaptureStore.state.collect { if (it.isCapturing) observedRunning = true } }
        val tracked = object : ContextWrapper(context) {
            override fun getApplicationContext(): Context = this
            override fun startForegroundService(intent: Intent): ComponentName? {
                sentStarts++
                val extras = requireNotNull(intent.extras)
                assertEquals(setOf("excludeSelf", "captureIpv6", "maxDurationMinutes", "maxSizeMegabytes",
                    "segmentSizeMegabytes", "allowedApplications", "tlsSettings"), extras.keySet())
                val json = requireNotNull(extras.getString("tlsSettings"))
                for (forbidden in listOf("PRIVATE KEY", "CLIENT_TRAFFIC_SECRET", "token")) {
                    assertFalse(json.contains(forbidden, true))
                }
                return super.startForegroundService(intent)
            }
        }
        packets = PacketRepository()
        model = PacketListViewModel(packets, CaptureSessionCoordinator(packets), tracked,
            captureVolumeFreeBytes = { freeBytes })
        instrumentation.runOnMainSync { models.put("tls315", model) }
    }

    @After fun cleanup() {
        try {
            shell("cmd statusbar collapse")
            if (LiveCaptureStore.state.value.isCapturing) {
                captureFile()?.let { captures += it.nameWithoutExtension }
                context.startService(Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP))
            }
            stopped()
        } finally {
            instrumentation.runOnMainSync { models.clear() }
            stateObserver.cancel()
            if (::packets.isInitialized) packets.closeFile()
            TlsCaManagerHolder.installForTest(null)
            captures.forEach { CaptureArtifactLifecycle(context).purge(it) }
            if (::caRoot.isInitialized) caRoot.deleteRecursively()
            keyStore().deleteEntry(alias)
            prefs().edit().apply {
                if (previousSettings == null) remove("settings") else putString("settings", previousSettings)
            }.commit()
            savedPreferences.forEach { (name, values) ->
                val preferences = context.getSharedPreferences(name, Context.MODE_PRIVATE)
                preferences.edit().clear().apply {
                    values.forEach { (key, value) -> when (value) {
                        is String -> putString(key, value)
                        is Boolean -> putBoolean(key, value)
                        is Int -> putInt(key, value)
                        is Long -> putLong(key, value)
                        is Float -> putFloat(key, value)
                        is Set<*> -> putStringSet(key, value.filterIsInstance<String>().toSet())
                        else -> error("Unsupported preference type")
                    } }
                }.commit()
                assertEquals(values, preferences.all)
            }
            shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        }
    }

    @Test fun missingCaAndLowStorageNeverStartAService() {
        screen(settings())
        click(R.string.start)
        await("CA gate") { model.tlsStartBlock.value == TlsStartBlockReason.CA_NOT_READY }
        themes("missing-ca", R.string.tls_capture_start_blocked_ca)
        assertEquals(0, sentStarts)
        assertFalse(observedRunning)
        assertFalse(LiveCaptureStore.state.value.isCapturing)
        assertNull(notification())
        generateCa()
        freeBytes = TlsStartGate.MIN_FREE_BYTES - 1
        click(R.string.start)
        await("storage gate") { model.tlsStartBlock.value == TlsStartBlockReason.STORAGE_LOW }
        themes("low-storage", R.string.tls_capture_start_blocked_storage)
        assertEquals(0, sentStarts)
        assertFalse(observedRunning)
        assertFalse(LiveCaptureStore.state.value.isCapturing)
        assertNull(notification())
        record("gates", JSONObject().put("ca", "CA_NOT_READY").put("storage", "STORAGE_LOW")
            .put("freeBytesInjected", freeBytes).put("foregroundServiceStarts", sentStarts))
    }

    @Test fun coldCaTargetCaptureNotificationStopAndAutomaticAnalysis() {
        assertNull(VpnService.prepare(context))
        assertArrayEquals(expected, body(exchange(SSLContext.getDefault(), false)))
        screen(settings().copy(tls = TlsCaptureSettings()))
        show(R.string.tls_capture_enable)
        compose.onNodeWithText(text(R.string.tls_capture_ca_missing)).assertDoesNotExist()
        themes("tls-off", R.string.tls_capture_enable)
        generateCa()
        compose.onNodeWithText(text(R.string.capture_apps_selected, 1)).assertExists()
        show(R.string.tls_capture_enable)
        tlsSwitch().performScrollTo().performClick()
        // The product picker deliberately excludes its own UID. Seed only that
        // synthetic client's allowlist, then choose its exact target on screen.
        show(R.string.tls_capture_include_label)
        compose.onAllNodes(hasSetTextAction())[0].performScrollTo().performTextInput(host)
        compose.onAllNodesWithText(text(R.string.tls_capture_rule_add))[0].performScrollTo().performClick()
        instrumentation.uiAutomation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK)
        click(R.string.start)
        running()
        val captureId = requireNotNull(captureFile()).nameWithoutExtension
        captures += captureId
        assertEquals(1, sentStarts)
        val frozen = model.loadLiveCaptureSettings()
        assertEquals(listOf(context.packageName), frozen.allowedApplications)
        assertTrue(frozen.tls.enabled)
        assertEquals(listOf(host), frozen.tls.includeHosts)
        assertEquals(TlsHostScope.ExplicitHosts, frozen.tls.hostScope)
        themes("running", R.string.tls_capture_mode_change_restart)
        tlsSwitch().performScrollTo().assertIsNotEnabled()
        instrumentation.runOnMainSync { model.startLiveCapture(settings().copy(tls = TlsCaptureSettings())) }
        assertEquals(1, sentStarts)
        val response = exchange(proxyClient(), true)
        assertArrayEquals(expected, body(response))
        settlePackets()
        val active = notification(R.string.capture_notification_tls_active)
        notificationShot("active")
        active.actions.single { it.title.toString() == text(R.string.capture_notification_stop) }.actionIntent.send()
        shell("cmd statusbar collapse")
        stopped()
        assertArrayEquals(expected, body(exchange(SSLContext.getDefault(), false)))
        assertNull(LiveCaptureStore.state.value.error)
        val manifest = (CaptureArtifactRepository(context).read(captureId) as CaptureArtifactState.Present).manifest
        assertTrue(manifest.captureIsComplete)
        assertTrue(manifest.tls.complete)
        assertTrue(manifest.secretsPersistedSequence > 0)
        assertNotNull(manifest.tls.secretsAssetId)
        val original = requireNotNull(captureFile())
        val before = sha256(original.readBytes())
        click(R.string.open_saved)
        await("automatic analysis") { model.openError.value != null || (model.savedCaptureOpenInfo.value != null &&
            model.openProgress.value == null && packets.currentAnalysisRevision().ready) }
        assertNull(model.openError.value)
        val info = requireNotNull(model.savedCaptureOpenInfo.value)
        assertTrue(info.decryptionComplete)
        assertFalse(info.contextIncomplete)
        val revision = packets.currentAnalysisRevision()
        val objects = packets.getHttpObjects()
        assertEquals(1, objects.size)
        assertArrayEquals(expected, packets.getHttpObjectPayload(objects.single().id, revision))
        val followed = packets.followTlsStream(objects.single().frameNumber, revision)
        assertTrue(followed.success)
        assertFalse(followed.incomplete)
        fun bytes(direction: TlsFollowDirection) = ByteArrayOutputStream().apply {
            followed.records.filter { it.direction == direction }.forEach { write(it.bytes) }
        }.toByteArray()
        assertArrayEquals(request, bytes(TlsFollowDirection.Client))
        assertArrayEquals(response, bytes(TlsFollowDirection.Server))
        assertEquals(before, sha256(original.readBytes()))
        for (theme in listOf(false, true)) {
            compose.runOnIdle { dark = theme }
            compose.onNodeWithText(info.message).assertIsDisplayed()
            shot("analysis-${if (theme) "dark" else "light"}")
        }
        click(R.string.close)
        record("capture", JSONObject().put("frames", info.totalFrames).put("captureComplete", true)
            .put("secretsComplete", true).put("persistedSequence", manifest.secretsPersistedSequence)
            .put("captureSha256", before).put("bodyBytes", expected.size).put("bodySha256", sha256(expected))
            .put("requestBytes", request.size).put("responseBytes", response.size).put("followByteEqual", true)
            .put("networkRestored", true).put("notificationPendingIntentUsed", true))
        if (args.getString("tls316Audit") == "true") auditProductAssets(captureId, original)
    }

    /** TLS-316: continue the same real VPN capture through the remaining asset lifecycle.
     * Byte/source and exporter checks use production APIs; their UI/SAF surfaces have separate
     * device walkthroughs. Only lengths, hashes and booleans leave this test, never runtime keys.
     */
    private fun auditProductAssets(captureId: String, original: File) {
        val revision = packets.currentAnalysisRevision()
        val copied = ByteArrayOutputStream()
        var selectedSources = 0
        var oldDetail: PacketDetailSnapshot? = null
        fun fields(node: ProtocolNode): List<ProtocolNode> = listOf(node) + node.children.flatMap(::fields)
        for (frame in 1..NativeEngine.getFrameCount(packets.currentSessionHandle())) {
            val detail = packets.getPacketDetailSnapshot(frame.toLong(), revision)
            for (node in fields(detail.root).filter { it.filter == "http.file_data" }) {
                val state = com.example.layanalyzer.viewmodel.PacketDataSourceState().open(revision, detail)
                val (source, range) = requireNotNull(
                    com.example.layanalyzer.viewmodel.PacketBytesSourceActions.fieldTarget(state, node))
                assertNotEquals("raw", source.id)
                val window = requireNotNull(com.example.layanalyzer.viewmodel.PacketBytesSourceActions.windowRead(range, source))
                val pending = state.switchSource(source.id).beginRange(window.first, window.last - window.first + 1)
                val token = requireNotNull(pending.request)
                val chunk = packets.readPacketDataSource(token.snapshot, source, token.offset, token.length, revision)
                val selected = pending.complete(token, chunk).selectField(node)
                copied.write(requireNotNull(com.example.layanalyzer.viewmodel.PacketBytesSourceActions.actionBytes(
                    selected, com.example.layanalyzer.viewmodel.PacketBytesSourceActions.actionRange(selected, true))))
                oldDetail = detail
                selectedSources++
            }
        }
        assertTrue(selectedSources > 0)
        assertArrayEquals(expected, copied.toByteArray())
        val raw = ByteArrayOutputStream()
        original.inputStream().use { TlsRawCaptureWriter.copy(it, raw) }
        assertArrayEquals(original.readBytes(), raw.toByteArray())
        val rawText = raw.toByteArray().toString(Charsets.ISO_8859_1)
        for (marker in listOf(expected.toString(Charsets.UTF_8), "CLIENT_RANDOM", "TRAFFIC_SECRET", "PRIVATE KEY")) {
            assertFalse("Default export contains sensitive material", rawText.contains(marker))
        }
        val bundle = ByteArrayOutputStream()
        TlsCaptureBundle(context).writeComplete(captureId, bundle, filtered = false, confirmed = true)
        val names = mutableSetOf<String>()
        java.util.zip.ZipInputStream(bundle.toByteArray().inputStream()).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                names += entry.name
                val bytes = zip.readBytes()
                assertFalse(bytes.toString(Charsets.ISO_8859_1).contains("PRIVATE KEY"))
                if (entry.name == "keys.log") assertTrue(KeyLogParser.parse(bytes.inputStream()) is KeyLogParseResult.Success)
            }
        }
        assertTrue(names.containsAll(listOf("keys.log", "manifest.json", "checksums.json")))
        assertEquals(1, names.count { it.endsWith(".pcap") })
        val artifacts = CaptureArtifactRepository(context)
        val recent = RecentCapture("TLS-316 synthetic capture", original.length(), artifacts.analysisFile(captureId).path, 0)
        instrumentation.runOnMainSync { model.closeFile(); model.openRecentCapture(recent) }
        await("TLS-316 reopen") { model.openError.value != null || (model.savedCaptureOpenInfo.value != null &&
            model.openProgress.value == null && packets.currentAnalysisRevision().ready) }
        assertNull(model.openError.value)
        val reopened = packets.getHttpObjects().single()
        assertArrayEquals(expected, packets.getHttpObjectPayload(reopened.id, packets.currentAnalysisRevision()))
        compose.waitForIdle()
        shot("product-reopened")
        instrumentation.runOnMainSync { model.dismissSavedCaptureOpenInfo(); model.closeFile(); model.deleteRecentCapture(recent) }
        val lifecycle = CaptureArtifactLifecycle(context)
        await("TLS-316 deletion journal") { lifecycle.cleanupEvents().any { it.captureId == captureId && it.completed } }
        assertNull(model.openError.value)
        assertFalse(artifacts.captureDirectory(captureId).exists())
        assertNull(TlsSecretStore(context).currentAsset(captureId))
        val stale = requireNotNull(oldDetail)
        try {
            packets.readPacketDataSource(requireNotNull(stale.snapshot), stale.sources.first(), 0, 1, revision)
            fail("Deleted capture served an old data source")
        } catch (_: StaleCaptureAnalysisException) { /* required negative control */ }
        compose.waitForIdle()
        shot("product-deleted")
        record("product-assets", JSONObject().put("selectedSources", selectedSources).put("copiedBodyBytes", copied.size())
            .put("copiedBodySha256", sha256(copied.toByteArray())).put("rawExportSha256", sha256(raw.toByteArray()))
            .put("defaultExportByteEqual", true).put("defaultExportHasSecrets", false)
            .put("completeBundleEntries", org.json.JSONArray(names.sorted())).put("reopenedBodyByteEqual", true)
            .put("captureDeleted", true).put("secretAssetDeleted", true).put("oldDataSourceRejected", true))
    }

    @Test fun deniedVpnAndStartupFailureNeverPublishRunning() {
        ca.ensureGenerated()
        shell("appops set ${context.packageName} ACTIVATE_VPN ignore")
        assertNotNull(VpnService.prepare(context))
        instrumentation.runOnMainSync { model.startLiveCapture(settings()) }
        await("denied VPN failure") { LiveCaptureStore.state.value.error != null }
        stopped()
        val deniedError = LiveCaptureStore.state.value.error
        assertArrayEquals(expected, body(exchange(SSLContext.getDefault(), false)))
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        LiveCaptureStore.clearError()
        // Destroy only this test's wrapping key after generation: real service
        // startup must report failure without replacing the CA or publishing RUNNING.
        keyStore().deleteEntry(alias)
        ContextCompat.startForegroundService(context, Intent(context, LiveCaptureVpnService::class.java).apply {
            putExtra(LiveCaptureVpnService.EXTRA_TLS_SETTINGS, TlsCaptureSettingsJson.encode(settings().tls))
            putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
        })
        await("CA startup failure") { LiveCaptureStore.state.value.error != null }
        stopped()
        assertEquals(TlsCaState.KEY_UNAVAILABLE, ca.status().state)
        assertFalse("Neither failed start may emit a transient RUNNING state", observedRunning)
        record("start-failures", JSONObject().put("noConsentError", deniedError)
            .put("startupError", LiveCaptureStore.state.value.error).put("runningAfterFailure", false)
            .put("networkRestored", true))
    }

    @Test fun stopDuringStartDoesNotStartLaterInTheBackground() {
        ca.ensureGenerated()
        assertNull(VpnService.prepare(context))
        instrumentation.runOnMainSync { model.startLiveCapture(settings()); model.stopLiveCapture() }
        // CA read yields from Main. Its continuation cannot resume until after Stop.
        Thread.sleep(2500)
        assertEquals("Cancelled start reached the service", 0, sentStarts)
        assertFalse(LiveCaptureStore.state.value.isCapturing)
        assertFalse(isVpn())
        assertFalse(observedRunning)
        assertNull(notification())
    }

    @Test fun systemRevocationAndTlsOffRestoreConnectivity() {
        assertNull(VpnService.prepare(context))
        freeBytes = 0
        screen(settings().copy(tls = TlsCaptureSettings()))
        click(R.string.start)
        running()
        captureFile()?.let { captures += it.nameWithoutExtension }
        val off = notification(R.string.capture_notification_text)
        assertEquals(TlsCaState.MISSING, ca.status().state)
        assertNull(model.tlsStartBlock.value)
        assertArrayEquals(expected, body(exchange(SSLContext.getDefault(), true)))
        notificationShot("tls-off")
        shell("cmd statusbar collapse")
        // Revoke this package's actual Android VPN consent. On API 30,
        // prepareVpn sees that the prepared owner is no longer pre-consented,
        // resets its TUN, and sends VpnService's revoke binder transaction.
        // No test calls service.onRevoke() or the application's Stop action.
        shell("appops set ${context.packageName} ACTIVATE_VPN ignore")
        assertNotNull("The platform must require consent again", VpnService.prepare(context))
        stopped()
        shot("system-revoked")
        assertArrayEquals(expected, body(exchange(SSLContext.getDefault(), false)))
        record("revoke", JSONObject().put("systemConsentRevoked", true).put("newConsentRequired", true)
            .put("injection", "ACTIVATE_VPN ignore + platform VpnService.prepare").put("networkRestored", true)
            .put("tlsOffCaState", ca.status().state.name).put("tlsOffFreeBytesInjected", freeBytes)
            .put("notificationHasStop", off.actions.isNotEmpty()))
    }

    @Test fun systemRevocationStopsAnInterceptingCapture() {
        assertNull(VpnService.prepare(context))
        ca.ensureGenerated()
        screen(settings())
        click(R.string.start)
        running()
        captureFile()?.let { captures += it.nameWithoutExtension }
        notification(R.string.capture_notification_tls_active)
        assertArrayEquals(expected, body(exchange(proxyClient(), true)))
        shell("appops set ${context.packageName} ACTIVATE_VPN ignore")
        assertNotNull(VpnService.prepare(context))
        stopped()
        assertArrayEquals(expected, body(exchange(SSLContext.getDefault(), false)))
        record("revoke", JSONObject().put("tlsEnabled", true).put("systemConsentRevoked", true)
            .put("newConsentRequired", true).put("networkRestored", true))
    }

    private fun settings() = LiveCaptureSettings(excludeSelf = false, allowedApplications = listOf(context.packageName),
        tls = TlsCaptureSettings(enabled = true, includeHosts = listOf(host)))
    private fun screen(initial: LiveCaptureSettings) {
        compose.setContent {
            val state by LiveCaptureStore.state.collectAsState()
            val blocked by model.tlsStartBlock.collectAsState()
            val info by model.savedCaptureOpenInfo.collectAsState()
            LayerAnalyzerTheme(darkTheme = dark) {
                LiveCaptureScreen(state, initial, null, null, {}, { withContext(Dispatchers.IO) { ca.status().state } },
                    blocked, model::clearTlsStartBlock, model::startLiveCapture, model::stopLiveCapture,
                    model::openSavedLiveCapture, {})
                info?.let { SavedCaptureOpenDialog(it, model::dismissSavedCaptureOpenInfo) }
            }
        }
    }
    private fun generateCa() {
        click(R.string.tls_ca_setup_open)
        click(R.string.tls_ca_setup_generate)
        await("CA generated") { ca.status().state == TlsCaState.READY }
        compose.waitForIdle()
        shot("ca-generated")
        click(R.string.tls_ca_setup_install)
        show(R.string.tls_ca_setup_install_no_result)
        shot("ca-install-guidance")
        click(R.string.close)
    }
    private fun text(res: Int, vararg args: Any) = context.getString(res, *args)
    private fun click(res: Int) {
        val node = compose.onNodeWithText(text(res))
        if (res !in setOf(R.string.start, R.string.stop, R.string.open_saved, R.string.close, R.string.done)) {
            node.performScrollTo()
        }
        node.performClick()
    }
    // Full screen order: exclude self, IPv6, TLS enabled, then TLS-specific switches.
    private fun tlsSwitch() = compose.onAllNodes(isToggleable())[2]
    private fun show(res: Int) {
        val node = compose.onNodeWithText(text(res)).performScrollTo().assertIsDisplayed()
        val layouts = mutableListOf<TextLayoutResult>()
        node.performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
        assertTrue(layouts.isNotEmpty())
        layouts.forEach { layout ->
            assertFalse(layout.didOverflowHeight)
            assertEquals(text(res).length, layout.getLineEnd(layout.lineCount - 1))
            for (line in 0 until layout.lineCount) {
                assertFalse(layout.isLineEllipsized(line))
                assertTrue(layout.getLineLeft(line) >= -1)
                assertTrue(layout.getLineRight(line) <= layout.size.width + 1)
            }
        }
    }
    private fun themes(name: String, res: Int) {
        for (value in listOf(false, true)) { compose.runOnIdle { dark = value }; show(res); shot("$name-${if (value) "dark" else "light"}") }
    }
    private fun shot(name: String) {
        Thread.sleep(300)
        val bitmap = instrumentation.uiAutomation.takeScreenshot()
        File(output, "$name.png").outputStream().use { assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)) }
        bitmap.recycle()
    }
    private fun notificationShot(name: String) {
        shell("cmd statusbar expand-notifications")
        await("notification drawer") { automationText().contains(text(R.string.capture_notification_title)) }
        val title = nodes(instrumentation.uiAutomation.rootInActiveWindow)
            .first { it.text?.toString() == text(R.string.capture_notification_title) }
        val content = notification()?.extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString()
        val body = nodes(instrumentation.uiAutomation.rootInActiveWindow).first { it.text?.toString() == content }
        val titleBounds = android.graphics.Rect().also { title.getBoundsInScreen(it) }
        val bodyBounds = android.graphics.Rect().also { body.getBoundsInScreen(it) }
        // Save only this card: unrelated device notifications are outside the evidence.
        val bitmap = instrumentation.uiAutomation.takeScreenshot()
        val top = (titleBounds.top - 24).coerceAtLeast(0)
        val bottom = (bodyBounds.bottom + 24).coerceAtMost(bitmap.height)
        val card = Bitmap.createBitmap(bitmap, 0, top, bitmap.width, bottom - top)
        File(output, "notification-$name.png").outputStream().use { card.compress(Bitmap.CompressFormat.PNG, 100, it) }
        card.recycle(); bitmap.recycle()
    }
    private fun notification() = context.getSystemService(NotificationManager::class.java).activeNotifications
        .singleOrNull { it.id == 4101 }?.notification
    private fun notification(res: Int): Notification {
        await("notification state") { notification()?.extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString() == text(res) }
        val result = requireNotNull(notification())
        assertEquals(text(R.string.capture_notification_title), result.extras.getCharSequence(Notification.EXTRA_TITLE)?.toString())
        assertTrue(result.flags and Notification.FLAG_ONGOING_EVENT != 0)
        assertEquals(1, result.actions.size)
        return result
    }
    private fun running() = await("VPN running") {
        LiveCaptureStore.state.value.error?.let { error(it) }
        LiveCaptureStore.state.value.isCapturing && isVpn()
    }
    private fun stopped() = await("VPN stopped") { !LiveCaptureStore.state.value.isCapturing && !isVpn() && notification() == null }
    private fun captureFile() = LiveCaptureStore.state.value.outputPath?.let(::File)
    private fun settlePackets() {
        var previous = -1L
        var changed = System.currentTimeMillis()
        await("TCP close settled") {
            val count = LiveCaptureStore.state.value.packetCount
            if (count != previous) { previous = count; changed = System.currentTimeMillis() }
            System.currentTimeMillis() - changed >= 750
        }
    }
    private fun proxyClient(): SSLContext {
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(ca.exportPublicCertificate().certificateDer.inputStream())
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("test-proxy", cert) }
        val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        return SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }
    }
    private fun exchange(ssl: SSLContext, vpn: Boolean): ByteArray {
        assertEquals(vpn, isVpn())
        Socket().use { raw ->
            val deadline = System.currentTimeMillis() + 5000
            while (true) {
                try { requireNotNull(connectivity.activeNetwork).bindSocket(raw); break }
                catch (e: SocketException) {
                    if (!vpn || !e.message.orEmpty().contains("EPERM") || System.currentTimeMillis() >= deadline) throw e
                    Thread.sleep(50)
                }
            }
            raw.connect(InetSocketAddress(host, 443), 10000); raw.soTimeout = 15000
            (ssl.socketFactory.createSocket(raw, host, 443, true) as SSLSocket).use { socket ->
                socket.enabledProtocols = arrayOf("TLSv1.3")
                socket.sslParameters = socket.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                socket.startHandshake()
                socket.outputStream.write(request); socket.outputStream.flush()
                return socket.inputStream.readBytes()
            }
        }
    }
    private fun body(response: ByteArray): ByteArray {
        val text = response.toString(Charsets.ISO_8859_1)
        assertTrue(text.startsWith("HTTP/1.1 200 "))
        val end = text.indexOf("\r\n\r\n"); assertTrue(end >= 0)
        val bytes = response.copyOfRange(end + 4, response.size)
        if (!text.substring(0, end).contains("transfer-encoding: chunked", true)) return bytes
        val buffer = okio.Buffer().write(bytes)
        return ByteArrayOutputStream().apply {
            while (true) {
                val length = buffer.readUtf8LineStrict().substringBefore(';').toLong(16)
                if (length == 0L) break
                require(length in 1..262144)
                write(buffer.readByteArray(length)); check(buffer.readUtf8LineStrict().isEmpty())
            }
        }.toByteArray()
    }
    private fun isVpn() = connectivity.getNetworkCapabilities(connectivity.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    private fun prefs() = context.getSharedPreferences("live_capture_settings", Context.MODE_PRIVATE)
    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun record(name: String, json: JSONObject) { File(output, "$name.json").writeText(json.toString(2)) }
    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun shell(command: String): String = instrumentation.uiAutomation.executeShellCommand(command).use {
        android.os.ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
    }
    private fun await(label: String, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 30000
        while (System.currentTimeMillis() < deadline) { if (condition()) return; Thread.sleep(50) }
        shot("failure")
        File(output, "failure-tree.txt").writeText(automationText())
        error("Timed out: $label")
    }
    private fun nodes(root: AccessibilityNodeInfo?): List<AccessibilityNodeInfo> =
        if (root == null) emptyList() else listOf(root) + (0 until root.childCount).flatMap { nodes(root.getChild(it)) }
    private fun automationText() = nodes(instrumentation.uiAutomation.rootInActiveWindow)
        .joinToString("\n") { "${it.className}: ${it.text ?: ""} | ${it.contentDescription ?: ""}" }
}
