// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import com.example.layanalyzer.capture.tls.SocksNioTlsGateway

import com.example.layanalyzer.capture.socks.SocksRuntimeLimits
import com.example.layanalyzer.BuildConfig

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import androidx.annotation.StringRes
import androidx.core.app.NotificationCompat
import com.example.layanalyzer.MainActivity
import com.example.layanalyzer.R
import com.example.layanalyzer.capture.tls.TlsCaManagerHolder
import com.example.layanalyzer.capture.tls.TlsCaptureCoordinator
import com.example.layanalyzer.capture.tls.TlsCaptureStart
import com.example.layanalyzer.capture.tls.TlsCaptureState
import com.example.layanalyzer.capture.tls.TlsCertificateManager
import com.example.layanalyzer.capture.tls.TlsConnectionPreviewStore
import com.example.layanalyzer.capture.tls.createTlsCaptureConnectionStore
import com.example.layanalyzer.capture.tls.TlsNetworkAccess
import com.example.layanalyzer.capture.tls.TlsSecretStore
import com.example.layanalyzer.capture.tls.TlsUpstreamCallbacks
import com.example.layanalyzer.capture.tls.UpstreamSocketProtector
import com.example.layanalyzer.model.CaptureMode
import com.example.layanalyzer.model.CaptureRetentionPolicy
import com.example.layanalyzer.model.CaptureTlsAssets
import com.example.layanalyzer.model.LiveCaptureManifestConfig
import com.example.layanalyzer.model.LiveCaptureState
import com.example.layanalyzer.model.PacketVantage
import com.example.layanalyzer.model.QuicPolicy
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureSettingsJson
import com.example.layanalyzer.model.TlsCaptureStatus
import com.example.layanalyzer.model.TlsErrorCode
import java.io.Closeable
import java.io.EOFException
import java.io.File
import java.io.FileDescriptor
import java.io.IOException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONObject

open class LiveCaptureVpnService : VpnService() {
    private val lifecycleLock = Any()
    private val stopRequested = AtomicBoolean(false)
    private val mainHandler = Handler(Looper.getMainLooper())
    // Only the main thread reads/writes these, together with onStartCommand and
    // the final foreground transition. The last request during stop wins.
    private var pendingStart: (() -> Unit)? = null
    private var latestStartId = 0
    private var destroyed = false

    @Volatile
    private var lifecycle = CaptureLifecycle.Idle

    @Volatile
    private var activeSession: CaptureSession? = null

    @Volatile
    private var captureThread: Thread? = null

    /**
     * The run's interception flag and the last TLS line posted to the ongoing
     * notification (TLS-315 step 3). Both belong to one run and are reset when a
     * run starts, so a stopped run's degradation is never shown for the next one.
     */
    @Volatile
    private var captureInterceptsTls = false

    @Volatile
    private var postedNotificationTlsState: CaptureNotificationTlsState? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId = startId
        when (intent?.action) {
            ACTION_STOP -> {
                pendingStart = null
                stopCapture()
            }
            else -> startCapture(
                excludeSelf = intent?.getBooleanExtra(EXTRA_EXCLUDE_SELF, true) ?: true,
                captureIpv6 = intent?.getBooleanExtra(EXTRA_CAPTURE_IPV6, false) ?: false,
                maxDurationMinutes = intent?.getIntExtra(EXTRA_MAX_DURATION_MINUTES, 15) ?: 15,
                maxSizeMegabytes = intent?.getIntExtra(EXTRA_MAX_SIZE_MEGABYTES, 256) ?: 256,
                segmentSizeMegabytes = intent?.getIntExtra(EXTRA_SEGMENT_SIZE_MEGABYTES, 64) ?: 64,
                allowedApplications = intent?.getStringArrayListExtra(EXTRA_ALLOWED_APPLICATIONS).orEmpty(),
                tlsSettingsJson = intent?.getStringExtra(EXTRA_TLS_SETTINGS)
            )
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        pendingStart = null
        stopCapture()
        super.onRevoke()
    }

    override fun onDestroy() {
        destroyed = true
        pendingStart = null
        stopCapture()
        super.onDestroy()
    }

    private fun startCapture(
        excludeSelf: Boolean,
        captureIpv6: Boolean,
        maxDurationMinutes: Int,
        maxSizeMegabytes: Int,
        segmentSizeMegabytes: Int,
        allowedApplications: List<String>,
        tlsSettingsJson: String?
    ) {
        val canStart = synchronized(lifecycleLock) {
            if (lifecycle != CaptureLifecycle.Idle) {
                false
            } else {
                lifecycle = CaptureLifecycle.Starting
                stopRequested.set(false)
                true
            }
        }
        try {
            // Every foreground-service start must be acknowledged, including a
            // request received while the preceding run is still stopping.
            val notificationState = if (canStart) CaptureNotificationTlsState.NOT_INTERCEPTING
                else postedNotificationTlsState ?: CaptureNotificationTlsState.NOT_INTERCEPTING
            startForeground(NOTIFICATION_ID, buildNotification(notificationState))
        } catch (error: Exception) {
            stopCapture()
            LiveCaptureStore.fail(error.message ?: getString(R.string.error_capture_notification))
            stopSelfResult(latestStartId)
            return
        }
        if (!canStart) {
            if (stopRequested.get() || lifecycle == CaptureLifecycle.Stopping) {
                pendingStart = {
                    startCapture(excludeSelf, captureIpv6, maxDurationMinutes, maxSizeMegabytes,
                        segmentSizeMegabytes, allowedApplications, tlsSettingsJson)
                }
            }
            return
        }

        captureInterceptsTls = false
        postedNotificationTlsState = CaptureNotificationTlsState.NOT_INTERCEPTING

        val worker = Thread(
            {
                runCapture(
                    excludeSelf,
                    captureIpv6,
                    maxDurationMinutes,
                    maxSizeMegabytes,
                    segmentSizeMegabytes,
                    allowedApplications,
                    tlsSettingsJson
                )
            },
            "LayerAnalyzer-VPN-Capture"
        )
        captureThread = worker
        worker.start()
    }

    private fun runCapture(
        excludeSelf: Boolean,
        captureIpv6: Boolean,
        maxDurationMinutes: Int,
        maxSizeMegabytes: Int,
        segmentSizeMegabytes: Int,
        allowedApplications: List<String>,
        tlsSettingsJson: String?
    ) {
        var session: CaptureSession? = null
        var captureStarted = false
        var failure: Throwable? = null
        var engineFd = -1
        var engineStarted = false
        var socksServer: DirectSocks5Server? = null
        var vpnInterface: ParcelFileDescriptor? = null
        var relayInterface: ParcelFileDescriptor? = null
        var packetSink: CapturePacketSink? = null
        var outputFile: File? = null
        var stopReason = "service_stopped"
        var tls: TlsCaptureCoordinator? = null
        var networkWatcher: CapturedNetworkWatcher? = null
        // The applied QUIC policy of this run, for the report (TLS-314). Null means
        // nothing was decided, so no UDP section is written.
        var udpInterventionPolicy: String? = null

        try {
            val captureStamp = System.currentTimeMillis()
            val captureId = "live-$captureStamp"
            // The request is decoded once, here, and the same frozen value decides the
            // write layout, the TLS stage and the forwarding-layer UDP rule (TLS-314),
            // so the interception the user sees and the datagrams that are dropped
            // cannot come from two different readings of one Intent.
            val requestedTls: TlsCaptureSettings = TlsCaptureSettingsJson
                .decode(tlsSettingsJson, allowedApplications)
                .settings
            captureInterceptsTls = requestedTls.enabled
            // A manifest capture lives in `filesDir/captures/<captureId>/`, the layout
            // the asset repository owns (§8.3, C08): a manifest segment is a *relative*
            // name inside the capture directory, so the PCAP has to be inside it or the
            // manifest could not name its own bytes. A TLS-disabled run keeps the
            // pre-manifest flat layout and the pre-manifest behaviour byte for byte
            // (C03 1, acceptance 2) — no directory, no manifest, no change.
            //
            // The file keeps the `<captureId>.pcap` name inside the directory: that is
            // what lets the existing open path derive the id from the file name
            // (`CaptureOpenPlanner.captureIdFor`), so a manifest capture is found by the
            // same rule whether it predates the manifest layout or not.
            val captureFile = if (requestedTls.enabled) {
                File(filesDir, "captures/$captureId/$captureId.pcap")
            } else {
                File(filesDir, "captures/$captureId.pcap")
            }.apply { parentFile?.mkdirs() }
            outputFile = captureFile
            // The manifest is written only for a run that actually intercepts. The
            // secrets asset is not known yet — it is named by recordSecretsAsset once
            // the sink has published a watermark, just before the manifest is committed.
            val manifestConfig = if (requestedTls.enabled) {
                LiveCaptureManifestConfig(
                    captureId = captureId,
                    captureMode = CaptureMode.ActiveTlsProxy,
                    packetVantage = PacketVantage.AppToLocalProxy,
                    retentionPolicy = if (requestedTls.retainSecrets) {
                        CaptureRetentionPolicy.KeepCaptureAndSecrets
                    } else {
                        CaptureRetentionPolicy.KeepCaptureTransientSecrets
                    },
                    tls = CaptureTlsAssets(enabled = true)
                )
            } else {
                null
            }
            // The TLS preview belongs to one capture: a new run — intercepted or
            // not — must never show the previous run's summary. The capture loop
            // below repopulates it (TLS-306), at most once per the connection
            // store's own C10 250 ms gate.
            TlsConnectionPreviewStore.clear()
            val upstream = snapshotUnderlyingNetwork()
            // One C05 network identity per run. It is compared for equality only —
            // by this run's upstream protector, its gateway frames and its events —
            // so a value that differs from every earlier run is what lets a late
            // callback from a stopped capture be refused (TLS-203/216).
            val networkGeneration = SystemClock.elapsedRealtime()
            networkWatcher = upstream.network?.let { network ->
                CapturedNetworkWatcher(network).also { it.register() }
            }

            // The TLS stage comes before the SOCKS hop (design §10.3) because the
            // hop's gateway channel is handed to it, and it stays before the VPN:
            // a TLS failure must never happen after the default route moved.
            val coordinator = createTlsCoordinator(
                captureId,
                networkGeneration,
                upstream,
                allowedApplications,
                requestedTls
            )
            tls = coordinator
            val gateway = when (val started = coordinator?.start()) {
                null, is TlsCaptureStart.Disabled -> null
                is TlsCaptureStart.Started -> started.gateway
                is TlsCaptureStart.Failed -> throw TlsCaptureStartException(started.errorCode)
            }
            ensureNotStopping()

            // One rule object for the run: TLS off yields PRESERVE, and interception
            // that cannot start throws above rather than reaching this line, so a
            // datagram is never dropped for a capture that is not intercepting
            // (C03 1).
            val udpPolicy = TlsInterceptionPolicy.udpPolicy(requestedTls)
            udpInterventionPolicy = TlsInterceptionPolicy.appliedQuicPolicy(requestedTls).wireName
            val directSocksServer = createDirectSocksServer(upstream.network, gateway, udpPolicy)
            socksServer = directSocksServer
            resourceSessionSnapshot = { directSocksServer.sessionStats() }
            directSocksServer.start(networkGeneration)
            CaptureStartupChecks.reached("socks")
            ensureNotStopping()

            val socketPair = Tun2SocksBridge.createPacketSocketPair()
                ?: throw IOException("Unable to create TUN forwarding relay.")
            if (socketPair.size != 2) {
                socketPair.forEach(::closeOwnedFd)
                throw IOException("Invalid TUN forwarding relay.")
            }

            engineFd = socketPair[1]
            val establishedRelay = ParcelFileDescriptor.adoptFd(socketPair[0])
            relayInterface = establishedRelay
            CaptureStartupChecks.reached("packet-pair")
            ensureNotStopping()

            val config = buildTun2SocksConfig(
                socksServerPort = directSocksServer.port,
                credentials = directSocksServer.credentials
            )
            val engineStartedSuccessfully = Tun2SocksBridge.start(engineFd, config)
            engineFd = -1 // Native now owns and closes this endpoint.
            if (!engineStartedSuccessfully) throw IOException("Unable to start TUN forwarding engine.")
            engineStarted = true
            CaptureStartupChecks.reached("hev")
            ensureNotStopping()

            val totalLimitBytes = maxSizeMegabytes.coerceIn(1, 4 * 1024).toLong() * 1024L * 1024L
            val segmentLimitBytes = segmentSizeMegabytes.coerceIn(1, maxSizeMegabytes.coerceAtLeast(1)).toLong() * 1024L * 1024L
            val establishedSink = CapturePacketSink(captureFile, segmentLimitBytes)
            packetSink = establishedSink
            CaptureStartupChecks.reached("pcap")
            ensureNotStopping()

            // Establish the default route only after every forwarding component
            // is ready. A native startup failure must never leave the device offline.
            val establishedVpn = establishVpn(
                excludeSelf = excludeSelf,
                captureIpv6 = captureIpv6,
                upstream = upstream,
                allowedApplications = allowedApplications
            ) ?: throw IOException("Unable to establish VPN capture interface.")
            vpnInterface = establishedVpn
            CaptureStartupChecks.reached("vpn")
            ensureNotStopping()

            val captureSession = CaptureSession(
                vpnInterface,
                establishedRelay,
                directSocksServer,
                establishedSink,
                coordinator
            )
            session = captureSession
            vpnInterface = null
            relayInterface = null
            socksServer = null
            packetSink = null
            engineStarted = false
            // The session owns the TLS run from here on: its close() is the one
            // that stops it, so the local reference is not used again.

            synchronized(lifecycleLock) {
                activeSession = captureSession
                lifecycle = if (stopRequested.get()) {
                    CaptureLifecycle.Stopping
                } else {
                    CaptureLifecycle.Running
                }
            }
            ensureNotStopping()

            CaptureStartupChecks.reached("publish")
            ensureNotStopping()
            LiveCaptureStore.start(captureFile.absolutePath, manifestConfig)
            captureStarted = true
            captureSession.startPumps()
            stopReason = waitForCaptureEnd(captureSession, maxDurationMinutes, totalLimitBytes, upstream.network, networkWatcher)
        } catch (_: CaptureStoppedException) {
            // User initiated stop during setup. The finally block closes partial resources.
        } catch (error: Throwable) {
            // Closing TUN/HEV during an explicit stop can wake a pump with an
            // IOException. It is the requested shutdown, not a capture failure.
            if (stopRequested.get()) stopReason = "requested_stop" else failure = error
        } finally {
            synchronized(lifecycleLock) { lifecycle = CaptureLifecycle.Stopping }
            if (engineFd >= 0) {
                closeOwnedFd(engineFd)
            }

            networkWatcher?.close()
            session?.close()
            session?.awaitPumps(PUMP_SHUTDOWN_TIMEOUT_MILLIS)
            session?.closeSink()
            if (session == null) {
                closeQuietly(vpnInterface)
                // A partially started HEV run can still wait on this listener's
                // control sockets. Release them before joining the native worker.
                closeQuietly(socksServer)
                if (engineStarted) {
                    runCatching { Tun2SocksBridge.stop() }
                }
                closeQuietly(relayInterface)
                closeQuietly(packetSink)
                // Reverse of the start order: whatever the TLS stage had opened is
                // released after the components that were started before it.
                closeTlsQuietly(tls)
                tls = null
            }

            val finalSocksStats = session?.socksSessionStats() ?: socksServer?.sessionStats()
            // Retain values only after stop, never the closed server and its workers.
            resourceSessionSnapshot = { finalSocksStats }
            synchronized(lifecycleLock) {
                if (activeSession === session) activeSession = null
            }

            // The sink has finished by now (session.close() above ran the TLS stop,
            // which is where the watermark is published), so the asset the manifest
            // may name is known. Recorded before stop()/fail(): those are the only
            // calls that commit the manifest, and a run whose sink never published
            // passes null rather than pointing at a directory the lease would refuse
            // (C08). A TLS-disabled run has no manifest configuration, so this is a
            // no-op for it.
            val finalTls = session?.tlsState()
            if (captureStarted) {
                LiveCaptureStore.recordSecretsAsset(
                    asset = finalTls?.secrets?.asset,
                    complete = finalTls?.secrets?.complete == true
                )
            }
            val finalNotificationTls = CaptureNotificationPlan.tlsState(
                enabled = captureInterceptsTls,
                status = finalTls?.status,
                secretsComplete = finalTls?.secrets?.complete == true,
                mitmSuspended = finalTls?.secrets?.mitmSuspended == true
            )

            when {
                failure != null && !stopRequested.get() -> {
                    LiveCaptureStore.fail(failure.message ?: "Capture forwarding failed.")
                }
                captureStarted -> LiveCaptureStore.stop()
            }
            if (captureStarted && outputFile != null) {
                writeCompletenessReport(
                    outputFile,
                    session?.captureSegments().orEmpty().ifEmpty { listOf(outputFile) },
                    captureIpv6,
                    allowedApplications,
                    if (failure != null) "failure" else stopReason,
                    session?.tlsState(),
                    udpInterventionPolicy,
                    // Read after close on purpose: the counters are plain totals,
                    // and the sockets that produced them are already gone.
                    session?.udpInterventionStats()
                        ?: socksServer?.udpInterventionStats()
                        ?: UdpInterventionStats(),
                    session?.socksSessionStats() ?: socksServer?.sessionStats(),
                    session?.nioStats() ?: socksServer?.nioStats(),
                    session?.socksRuntime() ?: socksServer?.runtimeLimits ?: SocksRuntimeLimits(),
                    session?.socksCloseFailed() == true
                )
                postCompletionNotification(LiveCaptureStore.state.value, finalNotificationTls)
            }

            CaptureStartupChecks.reached("finalize")
            mainHandler.post {
                // Do not expose Idle until the old run has finished publishing.
                // Serializing this with onStartCommand prevents an old worker
                // from removing the next run's foreground notification/service.
                synchronized(lifecycleLock) {
                    lifecycle = CaptureLifecycle.Idle
                    captureThread = null
                }
                val restart = if (destroyed) null else pendingStart
                pendingStart = null
                if (restart != null) {
                    restart()
                } else {
                    stopForegroundCompat()
                    stopSelfResult(latestStartId)
                }
            }
        }
    }

    private fun writeCompletenessReport(
        outputFile: File,
        segmentFiles: List<File>,
        captureIpv6: Boolean,
        allowedApplications: List<String>,
        stopReason: String,
        tlsState: TlsCaptureState?,
        udpPolicy: String?,
        udpInterventions: UdpInterventionStats,
        socksSessions: SocksSessionStats?,
        nio: com.example.layanalyzer.capture.socks.SocksNioTcpServer.Stats?,
        runtime: SocksRuntimeLimits,
        socksCloseFailed: Boolean
    ) {
        val state = LiveCaptureStore.state.value
        val report = JSONObject()
            .put("captureFile", outputFile.name)
            .put("segments", org.json.JSONArray().apply {
                segmentFiles.forEachIndexed { index, file ->
                    put(JSONObject().put("index", index + 1).put("file", file.name).put("bytes", file.length()))
                }
            })
            .put("segmentCount", segmentFiles.size)
            .put("linkType", "LINKTYPE_RAW")
            .put("ipScope", if (captureIpv6) "IPv4 and IPv6" else "IPv4")
            .put("forwardedProtocols", "TCP and UDP")
            .put("startedAtMillis", state.startedAtMillis)
            .put("stoppedAtMillis", state.stoppedAtMillis)
            .put("offeredPackets", state.offeredPacketCount)
            .put("writtenPackets", state.packetCount)
            .put("writtenBytes", state.byteCount)
            .put("droppedPackets", state.droppedPacketCount)
            .put("ioErrors", state.ioErrorCount)
            .put("lastIoError", state.lastIoError ?: JSONObject.NULL)
            .put("complete", state.captureIsComplete)
            .put("stopReason", stopReason)
            .put("applicationScope", if (allowedApplications.isEmpty()) "all routed apps" else allowedApplications)
            .apply {
                socksSessions?.let {
                    put("socks", JSONObject()
                        .put("rejectedHandshakes", it.rejectedHandshakes)
                        .put("rejectedTcpSessions", it.rejectedTcp)
                        .put("rejectedUdpSessions", it.rejectedUdp)
                        .put("expiredUdpAssociations", it.expiredUdp)
                        .put("serverId", it.serverId)
                        .put("running", it.running)
                        .put("handshakes", budgetJson(it.handshakes))
                        .put("tcp", budgetJson(it.tcp))
                        .put("udp", budgetJson(it.udp))
                        .put("failureEvents", JSONObject(it.failureEvents)))
                }
                tlsState?.let {
                    put("tls", it.toReportJson())
                    // The UDP rule is part of the interception, so it is reported
                    // with it: which rule was applied and how many datagrams it
                    // dropped. A forward is never counted as an intervention.
                    put(
                        "udpIntervention",
                        JSONObject()
                            .put("policy", udpPolicy ?: QuicPolicy.Preserve.wireName)
                            .put("blockedDatagrams", udpInterventions.blockedDatagrams)
                            .put("blockedBytes", udpInterventions.blockedBytes)
                    )
                }
            }
        CaptureCompletenessReport.append(report, runtime, socksSessions, nio, tlsState, socksCloseFailed)
        runCatching {
            File(outputFile.parentFile, "${outputFile.name}.report.json")
                .writeText(report.toString(2))
        }.onFailure { error ->
            LiveCaptureStore.recordIoError(error.message ?: "Unable to write capture completeness report.")
        }
    }

    /** Packet completeness, saved secrets and verified decryption are separate facts. */
    private fun TlsCaptureState.toReportJson(): JSONObject =
        if (status == TlsCaptureStatus.DISABLED) JSONObject() else CaptureCompletenessReport.tlsJson(this)

    private fun waitForCaptureEnd(
        session: CaptureSession,
        maxDurationMinutes: Int,
        sizeLimitBytes: Long,
        underlyingNetwork: Network?,
        networkWatcher: CapturedNetworkWatcher?
    ): String {
        val startedAt = SystemClock.elapsedRealtime()
        val durationLimit = maxDurationMinutes.coerceIn(1, 24 * 60) * 60_000L
        val diagnosticAt = SystemClock.elapsedRealtime() + FORWARDING_DIAGNOSTIC_DELAY_MILLIS
        var diagnosticChecked = false
        while (session.isForwarding()) {
            // The engine's bounded events and counters are folded in here rather
            // than on a thread of their own: the capture loop is already the one
            // place that knows the capture is alive, and a reader that dies with
            // the loop cannot outlive it (C10's 250 ms tick).
            session.pumpTls()
            // The TLS summary reaches the UI through the same 250 ms tick. The
            // publication itself is gated by the store's own C10 budget, so this
            // call cannot repaint Compose faster than once per interval, and a
            // capture without interception publishes nothing (TLS-306).
            session.publishTlsPreview()
            // The same tick keeps the notification's TLS line honest (TLS-315 step
            // 3): "interception is up" and "a secret could no longer be written, so
            // new connections pass through" are states of the run, and the user
            // should not have to open the app to learn the second one.
            refreshCaptureNotification(session)
            if (LiveCaptureStore.state.value.ioErrorCount > 0L) {
                // The asynchronous PCAP writer can fail while HEV is still
                // forwarding. End this capture through the common route-first
                // teardown instead of silently routing until the duration limit.
                throw IOException("Capture file write failed; capture stopped and evidence is incomplete.")
            }
            if (underlyingNetwork != null) {
                // Upstream sockets are bound to this network for the entire capture.
                // Once the VPN becomes active, re-ranking all physical networks can
                // choose a different candidate even though this network is still up.
                // The registered callback reports the loss promptly and this check
                // is the authoritative one; both lead to the same stop, and the
                // first version stops instead of migrating established TLS to
                // another network (§5.3, TLS-216 step 3).
                val capabilities = getSystemService(ConnectivityManager::class.java)
                    .getNetworkCapabilities(underlyingNetwork)
                if (networkWatcher?.isLost() == true ||
                    capabilities == null ||
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                ) {
                    LiveCaptureStore.fail("Underlying network lost; capture stopped and evidence is incomplete.")
                    stopRequested.set(true)
                    session.close()
                    return "network_lost"
                }
            }
            val elapsed = SystemClock.elapsedRealtime() - startedAt
            if (elapsed >= durationLimit || LiveCaptureStore.state.value.byteCount >= sizeLimitBytes) {
                Log.i(LOG_TAG, "Capture reached its configured limit; stopping automatically.")
                stopRequested.set(true)
                return if (elapsed >= durationLimit) "duration_limit" else "size_limit"
            }
            if (session.awaitPumps(PUMP_HEALTH_CHECK_MILLIS)) {
                session.pumpFailure()?.let { throw IOException("TUN packet relay failed.", it) }
                throw IOException("TUN packet relay stopped unexpectedly.")
            }
            if (!Tun2SocksBridge.isRunning()) {
                throw IOException("TUN forwarding engine stopped unexpectedly.")
            }
            if (!diagnosticChecked && SystemClock.elapsedRealtime() >= diagnosticAt) {
                val stats = runCatching { Tun2SocksBridge.getStats() }.getOrNull()
                if (stats != null && stats.size == 4 && stats[0] > 0L) {
                    val upstream = session.upstreamStats()
                    val warning = when {
                        stats[2] == 0L ->
                            "HEV consumed ${stats[0]} outbound packets (${stats[1]} bytes) " +
                                "but produced no packets for the VPN."
                        upstream.sentBytes == 0L ->
                            "HEV is exchanging packets with the VPN, but no payload reached " +
                                "a protected upstream socket."
                        upstream.receivedBytes == 0L ->
                            "Protected upstream sockets sent ${upstream.sentBytes} bytes but " +
                                "received no remote payload."
                        else -> null
                    }
                    warning?.let { Log.w(LOG_TAG, it) }
                }
                diagnosticChecked = true
            }
        }
        session.pumpFailure()?.let { throw IOException("TUN packet relay failed.", it) }
        return if (stopRequested.get()) "requested_stop" else "forwarding_stopped"
    }

    private fun postCompletionNotification(
        state: LiveCaptureState,
        tlsState: CaptureNotificationTlsState
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) return
        ensureNotificationChannel()
        val contentIntent = PendingIntent.getActivity(
            this,
            2,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val title = if (state.captureIsComplete) {
            getString(R.string.capture_complete_notification_title)
        } else {
            getString(R.string.capture_incomplete_notification_title)
        }
        val text = if (state.captureIsComplete) {
            getString(
                R.string.capture_complete_notification_text,
                state.packetCount.toString(),
                state.segmentPaths.size.coerceAtLeast(1).toString()
            )
        } else {
            getString(
                R.string.capture_incomplete_notification_text,
                state.droppedPacketCount.toString(),
                state.ioErrorCount.toString()
            )
        }
        // The completion notification carries the run's final TLS verdict when it
        // intercepted (TLS-315 step 3): a capture whose secrets were never written
        // is not reported as a clean decrypted capture, and the writer-failure case
        // says exactly what happened to new connections.
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(title)
            .setContentText(text)
            .setAutoCancel(true)
            .setContentIntent(contentIntent)
        if (tlsState != CaptureNotificationTlsState.NOT_INTERCEPTING) {
            val tlsLine = getString(notificationTlsText(tlsState))
            builder.setSubText(tlsLine)
            builder.setStyle(NotificationCompat.BigTextStyle().bigText(text))
        }
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID + 1, builder.build())
    }

    private fun stopCapture() {
        stopRequested.set(true)
        val session = synchronized(lifecycleLock) {
            if (lifecycle == CaptureLifecycle.Idle) {
                null
            } else {
                lifecycle = CaptureLifecycle.Stopping
                activeSession
            }
        }

        if (session == null) {
            // A stop during startup is a flag, not a second teardown: the capture
            // thread sees it between stages and runs its own finally, which is the
            // same release path a running capture takes. The TLS stage checks it
            // too (TlsCaptureCoordinator.cancellationRequested), so a stop that
            // arrives while the engine is coming up still ends with no engine left.
            if (captureThread == null) stopSelf()
            return
        }

        Thread(
            { session.close() },
            "LayerAnalyzer-VPN-Capture-Stop"
        ).also { it.start() }
    }

    /**
     * Releases the TLS stage and writes one summary line. Counters and fixed codes
     * only: a token, a secret or a private key can never reach here by
     * construction, and the line exists so a device run can be diagnosed without
     * a debugger.
     */
    private fun closeTlsQuietly(coordinator: TlsCaptureCoordinator?) {
        if (coordinator == null) return
        val state = runCatching { coordinator.stop() }.getOrElse { return }
        // One final, unthrottled publication: the run is over, and the preview must
        // show the stopped state's counters rather than the last 250 ms tick's
        // (§10.2). This is a state transition, not a per-byte refresh, so it does
        // not go through the interval gate.
        runCatching { TlsConnectionPreviewStore.publish(coordinator.connections.snapshot()) }
        if (state.status == TlsCaptureStatus.DISABLED) return
        Log.i(
            LOG_TAG,
            "TLS capture ${state.status.wireName}" +
                (state.errorCode?.let { " (${it.wireName})" } ?: "") +
                ": accepted=${state.connections.accepted}" +
                " proxied=${state.connections.proxied}" +
                " passthrough=${state.connections.passthrough}" +
                " failed=${state.connections.failed}" +
                " secrets=${state.connections.secretRecordsAccepted}/" +
                "${state.connections.secretRecordsPersisted}" +
                " complete=${state.secretsComplete}"
        )
    }

    private fun establishVpn(
        excludeSelf: Boolean,
        captureIpv6: Boolean,
        upstream: UnderlyingNetworkSnapshot,
        allowedApplications: List<String>
    ): ParcelFileDescriptor? {
        val scopedApplications = allowedApplications
            .filter { it.isNotBlank() }
            .distinct()
        if (allowedApplications.isNotEmpty() && scopedApplications.isEmpty()) {
            throw IOException(getString(R.string.error_capture_allowlist))
        }
        return Builder()
            .setSession(getString(R.string.vpn_session_name))
            .setMtu(TUN_MTU)
            .setBlocking(false)
            .addAddress(TUN_IPV4_ADDRESS, 32)
            .addRoute("0.0.0.0", 0)
            .apply {
                upstream.network?.let { setUnderlyingNetworks(arrayOf(it)) }
                if (captureIpv6) {
                    addAddress(TUN_IPV6_ADDRESS, 128)
                    addRoute("::", 0)
                } else {
                    // Keep IPv6 on the physical network when the user only
                    // requested IPv4 capture; otherwise VpnService blocks it.
                    allowFamily(OsConstants.AF_INET6)
                }
                upstream.dnsServers
                    .filter { it is Inet4Address || captureIpv6 }
                    .forEach { addDnsServer(it) }
                if (allowedApplications.isEmpty() && excludeSelf) {
                    runCatching { addDisallowedApplication(packageName) }
                }
                scopedApplications.forEach { app ->
                    addAllowedApplication(app)
                }
            }
            .establish()
    }

    @Suppress("DEPRECATION")
    private fun snapshotUnderlyingNetwork(): UnderlyingNetworkSnapshot {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        val activeNetwork = connectivity.activeNetwork
        val candidates = mutableListOf<Network>().apply {
            activeNetwork?.let { add(it) }
            addAll(connectivity.allNetworks)
        }.distinct()
        val physicalNetworks = candidates.filter { network ->
            connectivity.getNetworkCapabilities(network)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == false
        }
        val network = physicalNetworks.firstOrNull { it == activeNetwork }
            ?: physicalNetworks.firstOrNull { candidate ->
                connectivity.getNetworkCapabilities(candidate)
                    ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
            }
            ?: physicalNetworks.firstOrNull { candidate ->
                connectivity.getNetworkCapabilities(candidate)
                    ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
            }
            ?: physicalNetworks.firstOrNull()
        val dnsServers = network
            ?.let { connectivity.getLinkProperties(it)?.dnsServers }
            .orEmpty()
        return UnderlyingNetworkSnapshot(network, dnsServers)
    }

    private fun frozenSocksRuntime() = SocksRuntimeLimits(
        tcp = BuildConfig.SOCKS_TCP_LIMIT, udp = BuildConfig.SOCKS_UDP_LIMIT,
        authentication = BuildConfig.SOCKS_AUTH_LIMIT
    )

    internal open fun createDirectSocksServer(
        underlyingNetwork: Network?,
        tlsGateway: SocksNioTlsGateway?,
        udpPolicy: UdpDestinationPolicy = UdpDestinationPolicy.PRESERVE
    ): DirectSocks5Server {
        return DirectSocks5Server(
            prepareTcp = { socket ->
                if (!protect(socket)) throw IOException("Unable to protect SOCKS TCP socket.")
                underlyingNetwork?.bindSocket(socket)
            },
            prepareUdp = { socket ->
                if (!protect(socket)) throw IOException("Unable to protect SOCKS UDP socket.")
                underlyingNetwork?.bindSocket(socket)
            },
            resolveHost = { host ->
                underlyingNetwork?.getAllByName(host) ?: InetAddress.getAllByName(host)
            },
            tlsGateway = tlsGateway,
            udpPolicy = udpPolicy,
            runtimeLimits = frozenSocksRuntime()
        )
    }

    /**
     * The TLS stage of one capture (TLS-216, design §10.3), or null when the
     * request does not enable interception.
     *
     * [requested] is the run's frozen request, decoded once by the caller (C04:
     * unknown enums, bad ports and unusable rules decode to TLS off rather than
     * to "intercept everything"). An object that is not enabled is not a failure:
     * the capture runs exactly as it did before this feature existed, and nothing
     * here touches the Keystore, the secrets directory or the Go library.
     *
     * An *enabled* request that cannot be served is a different matter: the
     * coordinator reports a fixed code and the capture is refused, because
     * forwarding it silently would hand the user an evidence file that looks
     * decryptable and is not (§10.2, C03 7).
     */
    private fun createTlsCoordinator(
        captureId: String,
        networkGeneration: Long,
        upstream: UnderlyingNetworkSnapshot,
        allowedApplications: List<String>,
        requested: TlsCaptureSettings
    ): TlsCaptureCoordinator? {
        val connectionStore = createTlsCaptureConnectionStore(
            File(filesDir, "captures"), captureId, requested
        ) ?: return null
        return TlsCaptureCoordinator(
            captureId = captureId,
            settings = requested,
            allowedApplications = allowedApplications,
            network = upstream.network?.let { CapturedNetwork(it, networkGeneration) },
            certificates = { caManager() },
            secretStore = { TlsSecretStore(this) },
            connectionStore = connectionStore,
            cancellationRequested = { stopRequested.get() },
            socksRuntime = frozenSocksRuntime()
        )
    }

    /**
     * The capture's CA manager, one per process.
     *
     * `TlsCertificateManager.activeLeases` is an instance field (TLS-206), so a
     * second instance would let `reset` replace the root while a running capture
     * is still signing leaves with it — exactly the property §7.2 and TLS-206's
     * acceptance depend on. The single instance lives in
     * [com.example.layanalyzer.capture.tls.TlsCaManagerHolder] precisely so that
     * every caller which may reset the root (this service and the P3 settings
     * wizard, TLS-305) shares it rather than each minting its own.
     *
     * The secrets store is deliberately *not* shared the same way: its locking is
     * already process-wide inside `TlsSecretStore`, and a live sink belongs to one
     * capture.
     */
    private fun caManager(): TlsCertificateManager = TlsCaManagerHolder.get(this)

    /**
     * The captured physical network for one TLS run: the same protect-then-bind
     * contract the direct SOCKS path uses (§5.3), with the run's generation frozen
     * into it.
     *
     * [close] is what refuses a late callback: once a capture is stopping, the
     * snapshot is gone, so a preparation that arrives afterwards is answered with
     * `NETWORK_CHANGED` instead of being served on a network this capture no
     * longer forwards through. A late callback from an *earlier* run of this
     * process cannot be confused with this one either, because its generation
     * differs and is never re-issued.
     */
    private inner class CapturedNetwork(
        network: Network,
        override val generation: Long
    ) : TlsNetworkAccess {
        private val live = AtomicReference(UpstreamSocketProtector.NetworkSnapshot(network, generation))
        private val protector = UpstreamSocketProtector(
            currentNetwork = { live.get() },
            protect = { fd -> protect(fd) }
        )

        override val upstream: TlsUpstreamCallbacks get() = protector

        override fun prepareHopSocket(socket: Socket) {
            // §5.2: the gateway hop is loopback, so it is protected but never bound
            // to the physical network; a refused protect fails the connection
            // instead of letting it be captured by this very VPN.
            if (!protect(socket)) throw IOException("Unable to protect the TLS gateway hop.")
        }

        override fun close() {
            live.set(null)
        }
    }

    /**
     * Watches the one physical network this capture forwards through (TLS-216
     * step 3). The callback only records the loss: the shutdown belongs to the
     * capture loop, so a Connectivity thread never blocks inside a teardown.
     * Registered before the route exists and released in the same `finally` that
     * releases everything else, so a stopped capture leaves no registered
     * callback behind.
     */
    private inner class CapturedNetworkWatcher(private val watched: Network) : Closeable {
        private val lost = AtomicBoolean(false)
        private val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onLost(network: Network) {
                if (network == watched) lost.set(true)
            }
        }

        fun register() {
            runCatching {
                getSystemService(ConnectivityManager::class.java).registerNetworkCallback(
                    NetworkRequest.Builder()
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                        .build(),
                    callback
                )
            }.onFailure {
                // The periodic capability check below is the authoritative one, so a
                // refused registration costs promptness, never correctness.
                Log.w(LOG_TAG, "Unable to register a network-loss callback; relying on the periodic check.")
            }
        }

        fun isLost(): Boolean = lost.get()

        override fun close() {
            runCatching {
                getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(callback)
            }
        }
    }

    private fun ensureNotStopping() {
        if (stopRequested.get()) throw CaptureStoppedException()
    }

    private fun buildNotification(tlsState: CaptureNotificationTlsState): Notification {
        ensureNotificationChannel()
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, javaClass).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(getString(R.string.capture_notification_title))
            .setContentText(getString(notificationTlsText(tlsState)))
            .setOngoing(true)
            .setContentIntent(contentIntent)
            .addAction(R.mipmap.ic_launcher, getString(R.string.capture_notification_stop), stopIntent)
            .build()
    }

    /**
     * The ongoing notification's one TLS line (TLS-315 step 3): a fixed state name,
     * never a count, a destination or a secret byte. The stop action is on every
     * variant of the notification, so "stop from the notification" keeps working
     * whatever the TLS state says.
     */
    @StringRes
    private fun notificationTlsText(state: CaptureNotificationTlsState): Int = when (state) {
        CaptureNotificationTlsState.NOT_INTERCEPTING -> R.string.capture_notification_text
        CaptureNotificationTlsState.INTERCEPTING -> R.string.capture_notification_tls_active
        CaptureNotificationTlsState.DEGRADED -> R.string.capture_notification_tls_degraded
        CaptureNotificationTlsState.FAILED -> R.string.capture_notification_tls_failed
    }

    /**
     * Keeps the ongoing notification's TLS line truthful (TLS-315 step 3). It is
     * driven by the capture loop's own 250 ms tick and reposts only when the state
     * actually changes, so a long capture does not rewrite the notification while
     * nothing is different. A refused/absent POST_NOTIFICATIONS permission leaves
     * the foreground service untouched; it only means the line is not visible.
     */
    private fun refreshCaptureNotification(session: CaptureSession) {
        val tls = session.tlsState()
        val state = CaptureNotificationPlan.tlsState(
            enabled = captureInterceptsTls,
            status = tls?.status,
            secretsComplete = tls?.secrets?.complete == true,
            mitmSuspended = tls?.secrets?.mitmSuspended == true
        )
        if (state == postedNotificationTlsState) return
        postedNotificationTlsState = state
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification(state))
    }

    private fun ensureNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(CHANNEL_ID, getString(R.string.capture_notification_channel), NotificationManager.IMPORTANCE_LOW)
        manager.createNotificationChannel(channel)
    }

    private fun stopForegroundCompat() {
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private inner class CaptureSession(
        private val vpnInterface: ParcelFileDescriptor,
        private val relayInterface: ParcelFileDescriptor,
        private val socksServer: DirectSocks5Server,
        private val sink: CapturePacketSink,
        private val tls: TlsCaptureCoordinator?
    ) : Closeable {
        private val forwarding = AtomicBoolean(true)
        private val closed = AtomicBoolean(false)
        private val closeFinished = CountDownLatch(1)
        private val pumpsFinished = CountDownLatch(2)
        private val failureLock = Any()

        @Volatile
        private var failure: Throwable? = null

        fun startPumps() {
            Thread(
                {
                    pump(
                        source = vpnInterface.fileDescriptor,
                        destination = relayInterface.fileDescriptor
                    )
                },
                "LayerAnalyzer-TUN-Outbound"
            ).start()
            Thread(
                {
                    pump(
                        source = relayInterface.fileDescriptor,
                        destination = vpnInterface.fileDescriptor
                    )
                },
                "LayerAnalyzer-TUN-Inbound"
            ).start()
        }

        private fun pump(source: FileDescriptor, destination: FileDescriptor) {
            val buffer = ByteArray(MAX_PACKET_SIZE)
            try {
                while (forwarding.get()) {
                    val length = readPacket(source, buffer)
                    if (length == 0) continue
                    // Snapshot before delivery: the peer can immediately ACK on
                    // the other pump. Recording after write lets that ACK reach
                    // the PCAP before the data it acknowledges; Wireshark then
                    // treats the delayed ServerHello as a spurious retransmit
                    // and cannot decrypt an otherwise complete TLS connection.
                    // record only copies into the bounded queue (no disk I/O).
                    sink.record(buffer, length)
                    writePacket(destination, buffer, length)
                }
            } catch (error: Throwable) {
                if (forwarding.get()) {
                    Log.e(LOG_TAG, "TUN relay stopped on ${Thread.currentThread().name}.", error)
                    synchronized(failureLock) {
                        if (failure == null) failure = error
                    }
                    forwarding.set(false)
                }
            } finally {
                pumpsFinished.countDown()
            }
        }

        fun isForwarding(): Boolean = forwarding.get()

        fun awaitPumps(timeoutMillis: Long): Boolean =
            pumpsFinished.await(timeoutMillis, TimeUnit.MILLISECONDS)

        fun pumpFailure(): Throwable? = synchronized(failureLock) { failure }

        fun upstreamStats(): DirectSocks5Server.UpstreamStats = socksServer.stats()

        fun socksSessionStats(): SocksSessionStats = socksServer.sessionStats()

        fun nioStats() = socksServer.nioStats()
        fun socksRuntime() = socksServer.runtimeLimits
        @Volatile private var socksCloseFailed = false
        fun socksCloseFailed(): Boolean = socksCloseFailed

        /** The run's UDP/443 interventions, for the report (TLS-314). */
        fun udpInterventionStats(): UdpInterventionStats =
            socksServer.udpInterventionStats()

        fun pumpTls() {
            tls?.pump()
        }

        /**
         * Hands the run's TLS summary to the in-process preview store, if the store
         * says enough time has passed since the last publication (TLS-306). The
         * gate is the store's own, so nothing here adds a second throttle, and a
         * run without interception has no store to publish.
         */
        fun publishTlsPreview() {
            val store = tls?.connections ?: return
            TlsConnectionPreviewStore.publishIfDue(store)
        }

        /** The finished run's fixed codes and counters, for the completeness report. */
        fun tlsState(): TlsCaptureState? = tls?.state()

        fun closeSink() {
            sink.close()
        }

        fun captureSegments(): List<File> = sink.segmentFiles()

        override fun close() {
            if (!closed.compareAndSet(false, true)) {
                awaitCloseFinished()
                return
            }

            try {
                forwarding.set(false)

                // Tear down Android's default route first so shutdown latency in
                // HEV or the SOCKS relays cannot interrupt normal connectivity.
                closeQuietly(vpnInterface)
                // HEV may still be authenticating/setting up a UDP association.
                // Do not join it while its SOCKS peer is kept alive: closing NIO
                // first wakes pending native socket I/O with EOF, including a
                // handshake that races HEV's timeout-based cancellation.
                runCatching { socksServer.close() }.onFailure { socksCloseFailed = true }
                runCatching { Tun2SocksBridge.stop() }
                closeQuietly(relayInterface)
                // The TLS engine comes last and only after the SOCKS hop is gone:
                // no connection can be dispatched to it any more, so its bounded
                // stop is draining rather than interrupting anything. The route was
                // already released above, which is what keeps §10.3's "the user's
                // network is back before the writers finish" true.
                closeTlsQuietly(tls)
            } finally {
                closeFinished.countDown()
            }
        }

        private fun awaitCloseFinished() {
            var interrupted = false
            while (true) {
                try {
                    closeFinished.await()
                    break
                } catch (_: InterruptedException) {
                    interrupted = true
                }
            }
            if (interrupted) Thread.currentThread().interrupt()
        }
    }

    private class CapturePacketSink(
        private val firstOutputFile: File,
        private val segmentLimitBytes: Long
    ) : Closeable {
        private val writer = RotatingPcapWriter(firstOutputFile, segmentLimitBytes) { file ->
            LiveCaptureStore.recordSegment(file.absolutePath)
        }
        private val queue = ArrayBlockingQueue<CapturedPacket>(CAPTURE_QUEUE_CAPACITY)
        private val packetBuffers = ArrayBlockingQueue<ByteArray>(CAPTURE_QUEUE_CAPACITY)
        private val queueLock = Any()
        private val closeStarted = AtomicBoolean(false)
        private var acceptingPackets = true
        @Volatile private var drainedSuccessfully = false

        private val writerThread = Thread(
            { writeQueuedPackets() },
            "LayerAnalyzer-PCAP-Writer"
        ).apply {
            isDaemon = true
        }

        init {
            try {
                repeat(CAPTURE_QUEUE_CAPACITY) {
                    packetBuffers.offer(ByteArray(CAPTURE_BUFFER_SIZE))
                }
                writerThread.start()
            } catch (error: Throwable) {
                runCatching { writer.close() }.onFailure { closeError ->
                    LiveCaptureStore.recordIoError(closeError.message ?: "Unable to finalize the capture file.")
                }
                throw error
            }
        }

        fun segmentFiles(): List<File> = writer.segmentFiles()

        fun record(bytes: ByteArray, length: Int) {
            val safeLength = length.coerceIn(0, bytes.size)
            LiveCaptureStore.recordOffered()
            synchronized(queueLock) {
                if (!acceptingPackets) {
                    LiveCaptureStore.recordDropped()
                    return
                }
                val pooledBuffer = packetBuffers.poll()
                val packetBytes = if (pooledBuffer != null && pooledBuffer.size >= safeLength) {
                    pooledBuffer
                } else {
                    pooledBuffer?.let(::recycleBuffer)
                    ByteArray(safeLength)
                }
                System.arraycopy(bytes, 0, packetBytes, 0, safeLength)
                val packet = CapturedPacket(System.currentTimeMillis(), packetBytes, safeLength)
                if (!queue.offer(packet)) {
                    recycleBuffer(packetBytes)
                    LiveCaptureStore.recordDropped()
                }
            }
        }

        override fun close() {
            if (!closeStarted.compareAndSet(false, true)) return
            synchronized(queueLock) {
                acceptingPackets = false
            }
            joinWriter(PCAP_WRITER_SHUTDOWN_TIMEOUT_MILLIS)
            if (writerThread.isAlive) {
                writerThread.interrupt()
                joinWriter(PCAP_WRITER_INTERRUPT_TIMEOUT_MILLIS)
            }
            // Publish only after this sink has finished, before this capture's stop
            // commits its manifest. A late/timed-out writer cannot finalize a new run.
            if (!writerThread.isAlive && drainedSuccessfully) LiveCaptureStore.recordWritersDrained()
        }

        private fun writeQueuedPackets() {
            var drained = false
            try {
                while (true) {
                    val packet = queue.poll(PCAP_WRITER_POLL_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
                    if (packet != null) {
                        try {
                            writer.writePacket(packet.timestampMillis, packet.bytes, packet.length)
                            LiveCaptureStore.recordPacket(packet.timestampMillis, packet.bytes, packet.length)
                        } finally {
                            recycleBuffer(packet.bytes)
                        }
                        continue
                    }

                    val writerDrained = synchronized(queueLock) {
                        !acceptingPackets && queue.isEmpty()
                    }
                    if (writerDrained) {
                        drained = true
                        break
                    }
                }
            } catch (_: InterruptedException) {
                // Closing the capture is allowed to discard a backlog rather than block traffic.
            } catch (error: IOException) {
                LiveCaptureStore.recordIoError(error.message ?: "Capture file write failed.")
            } finally {
                var discarded = 0L
                synchronized(queueLock) {
                    acceptingPackets = false
                    while (true) {
                        val pending = queue.poll() ?: break
                        discarded += 1L
                        recycleBuffer(pending.bytes)
                    }
                }
                LiveCaptureStore.recordDropped(discarded)
                runCatching { writer.close() }
                    .onSuccess { drainedSuccessfully = drained && discarded == 0L }
                    .onFailure { error ->
                        LiveCaptureStore.recordIoError(error.message ?: "Unable to finalize the capture file.")
                    }
            }
        }

        private fun recycleBuffer(buffer: ByteArray) {
            if (buffer.size == CAPTURE_BUFFER_SIZE) {
                packetBuffers.offer(buffer)
            }
        }

        private fun joinWriter(timeoutMillis: Long) {
            try {
                writerThread.join(timeoutMillis)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }

        private data class CapturedPacket(
            val timestampMillis: Long,
            val bytes: ByteArray,
            val length: Int
        )

        private companion object {
            const val CAPTURE_QUEUE_CAPACITY = 512
            const val CAPTURE_BUFFER_SIZE = 2_048
            const val PCAP_WRITER_POLL_TIMEOUT_MILLIS = 100L
            const val PCAP_WRITER_SHUTDOWN_TIMEOUT_MILLIS = 2_000L
            const val PCAP_WRITER_INTERRUPT_TIMEOUT_MILLIS = 250L
        }
    }

    private data class UnderlyingNetworkSnapshot(
        val network: Network?,
        val dnsServers: List<InetAddress>
    )

    private enum class CaptureLifecycle {
        Idle,
        Starting,
        Running,
        Stopping
    }

    private class CaptureStoppedException : Exception()

    /** The TLS stage asked for interception and could not provide it. */
    private class TlsCaptureStartException(val errorCode: TlsErrorCode) : Exception(
        "TLS decryption could not start (${errorCode.wireName}); the capture was not started."
    )

    companion object {
        @Volatile
        private var resourceSessionSnapshot: () -> SocksSessionStats? = { null }

        /** Internal diagnostics: one server lifetime, including its last stopped snapshot. */
        internal fun socksResourceSnapshot(): SocksSessionStats? = resourceSessionSnapshot()

        private fun budgetJson(value: SocksBudgetStats) = JSONObject()
            .put("current", value.current).put("peak", value.peak).put("limit", value.limit)

        /**
         * HEV's SOCKS5 client requires both halves of RFC 1929 credentials or neither
         * (`hev_config_parse_socks5()` rejects a lone field), so the pair is always
         * written together. The values are alphanumeric, hence safe inside single
         * quotes, and they stay in this in-memory document: never in the capture
         * manifest, the completeness report or logcat.
         *
         * `log-level: warn` is part of the secret handling, not cosmetic:
         * `hev_socks5_session_run()` prints the pair at debug level when it installs
         * them, so raising HEV to debug would put the credentials into logcat.
         */
        internal fun buildTun2SocksConfig(
            socksServerPort: Int,
            credentials: SocksCredentials
        ): String = """
            tunnel:
              mtu: $TUN_MTU
            socks5:
              address: '127.0.0.1'
              port: $socksServerPort
              udp: 'udp'
              username: '${credentials.username}'
              password: '${credentials.password}'
            misc:
              connect-timeout: 10000
              tcp-read-write-timeout: 300000
              udp-read-write-timeout: 60000
              log-file: stderr
              log-level: warn
        """.trimIndent()

        const val ACTION_STOP = "com.example.layanalyzer.capture.STOP"
        const val EXTRA_EXCLUDE_SELF = "excludeSelf"
        const val EXTRA_CAPTURE_IPV6 = "captureIpv6"
        const val EXTRA_MAX_DURATION_MINUTES = "maxDurationMinutes"
        const val EXTRA_MAX_SIZE_MEGABYTES = "maxSizeMegabytes"
        const val EXTRA_SEGMENT_SIZE_MEGABYTES = "segmentSizeMegabytes"
        const val EXTRA_ALLOWED_APPLICATIONS = "allowedApplications"

        /**
         * The frozen TLS settings of one capture, as `TlsCaptureSettingsJson.encode`
         * writes them (TLS-216 step 4).
         *
         * Absent means no interception, which is what every entry point sends today
         * — the settings UI and its persistence belong to P3 (TLS-304), so nothing
         * here reads a user preference, and a capture never starts intercepting
         * because a default changed. An object that does not enable TLS, or one the
         * validator rejects, is also no interception (C04). Only an enabled object
         * reaches the engine, and only a test or the future settings screen puts one
         * in this extra.
         */
        const val EXTRA_TLS_SETTINGS = "tlsSettings"

        /** Process-wide CA state: `activeLeases` is per instance, so the single
         * manager lives in [com.example.layanalyzer.capture.tls.TlsCaManagerHolder]
         * and not on this service. */
        private const val CHANNEL_ID = "live_capture"
        private const val LOG_TAG = "LayAnalyzer-Capture"
        private const val NOTIFICATION_ID = 4101
        private const val TUN_MTU = 1500
        private const val TUN_IPV4_ADDRESS = "10.111.0.2"
        private const val TUN_IPV6_ADDRESS = "fd00:111:222::2"
        private const val MAX_PACKET_SIZE = 65_535
        private const val PUMP_HEALTH_CHECK_MILLIS = 250L
        private const val PUMP_SHUTDOWN_TIMEOUT_MILLIS = 2_000L
        private const val FORWARDING_DIAGNOSTIC_DELAY_MILLIS = 5_000L
    }
}

private const val PACKET_POLL_TIMEOUT_MILLIS = 500

private fun readPacket(fd: FileDescriptor, buffer: ByteArray): Int {
    val pollFd = StructPollfd().apply {
        this.fd = fd
        events = OsConstants.POLLIN.toShort()
    }
    val ready = try {
        Os.poll(arrayOf(pollFd), PACKET_POLL_TIMEOUT_MILLIS)
    } catch (error: ErrnoException) {
        throw IOException("Unable to poll packet relay.", error)
    }
    if (ready == 0) return 0

    val revents = pollFd.revents.toInt() and 0xffff
    val fatalEvents = OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL
    if ((revents and fatalEvents) != 0) throw EOFException("Packet relay closed.")
    if ((revents and OsConstants.POLLIN) == 0) return 0

    return try {
        Os.read(fd, buffer, 0, buffer.size)
    } catch (error: ErrnoException) {
        if (
            error.errno == OsConstants.EAGAIN ||
            error.errno == OsConstants.EINTR
        ) {
            0
        } else {
            throw IOException("Unable to read packet relay.", error)
        }
    }
}

private fun writePacket(fd: FileDescriptor, buffer: ByteArray, length: Int) {
    while (true) {
        try {
            val written = Os.write(fd, buffer, 0, length)
            if (written == length) return
            if (written == 0) {
                waitForWritablePacketRelay(fd)
                continue
            }
            // Both TUN and the SOCK_SEQPACKET relay require one complete IP
            // packet per write. Splitting a short write would corrupt framing.
            throw IOException("Packet relay performed a short write.")
        } catch (error: ErrnoException) {
            if (error.errno == OsConstants.EINTR) continue
            if (
                error.errno == OsConstants.EAGAIN
            ) {
                waitForWritablePacketRelay(fd)
                continue
            }
            throw IOException("Unable to write packet relay.", error)
        }
    }
}

private fun waitForWritablePacketRelay(fd: FileDescriptor) {
    val pollFd = StructPollfd().apply {
        this.fd = fd
        events = OsConstants.POLLOUT.toShort()
    }
    while (true) {
        val ready = try {
            Os.poll(arrayOf(pollFd), PACKET_POLL_TIMEOUT_MILLIS)
        } catch (error: ErrnoException) {
            throw IOException("Unable to poll packet relay for writing.", error)
        }
        if (ready == 0) continue

        val revents = pollFd.revents.toInt() and 0xffff
        val fatalEvents = OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL
        if ((revents and fatalEvents) != 0) throw EOFException("Packet relay closed.")
        if ((revents and OsConstants.POLLOUT) != 0) return
    }
}

private fun closeQuietly(closeable: Closeable?) {
    runCatching { closeable?.close() }
}

private fun closeOwnedFd(fd: Int) {
    runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
}
