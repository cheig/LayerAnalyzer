// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.layanalyzer.MainActivity
import com.example.layanalyzer.R
import com.example.layanalyzer.model.LiveCaptureState
import java.io.Closeable
import java.io.EOFException
import java.io.File
import java.io.FileDescriptor
import java.io.IOException
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONObject

class LiveCaptureVpnService : VpnService() {
    private val lifecycleLock = Any()
    private val stopRequested = AtomicBoolean(false)

    @Volatile
    private var lifecycle = CaptureLifecycle.Idle

    @Volatile
    private var activeSession: CaptureSession? = null

    @Volatile
    private var captureThread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopCapture()
            else -> startCapture(
                excludeSelf = intent?.getBooleanExtra(EXTRA_EXCLUDE_SELF, true) ?: true,
                captureIpv6 = intent?.getBooleanExtra(EXTRA_CAPTURE_IPV6, false) ?: false,
                maxDurationMinutes = intent?.getIntExtra(EXTRA_MAX_DURATION_MINUTES, 15) ?: 15,
                maxSizeMegabytes = intent?.getIntExtra(EXTRA_MAX_SIZE_MEGABYTES, 256) ?: 256,
                segmentSizeMegabytes = intent?.getIntExtra(EXTRA_SEGMENT_SIZE_MEGABYTES, 64) ?: 64,
                allowedApplications = intent?.getStringArrayListExtra(EXTRA_ALLOWED_APPLICATIONS).orEmpty()
            )
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        stopCapture()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopCapture()
        super.onDestroy()
    }

    private fun startCapture(
        excludeSelf: Boolean,
        captureIpv6: Boolean,
        maxDurationMinutes: Int,
        maxSizeMegabytes: Int,
        segmentSizeMegabytes: Int,
        allowedApplications: List<String>
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
        if (!canStart) return

        try {
            startForeground(NOTIFICATION_ID, buildNotification())
        } catch (error: Exception) {
            synchronized(lifecycleLock) {
                lifecycle = CaptureLifecycle.Idle
            }
            LiveCaptureStore.fail(error.message ?: getString(R.string.error_capture_notification))
            stopSelf()
            return
        }

        val worker = Thread(
            { runCapture(excludeSelf, captureIpv6, maxDurationMinutes, maxSizeMegabytes, segmentSizeMegabytes, allowedApplications) },
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
        allowedApplications: List<String>
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

        try {
            val captureFile = File(filesDir, "captures/live-${System.currentTimeMillis()}.pcap").apply {
                parentFile?.mkdirs()
            }
            outputFile = captureFile
            val upstream = snapshotUnderlyingNetwork()
            val directSocksServer = createDirectSocksServer(upstream.network)
            socksServer = directSocksServer
            directSocksServer.start()
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

            val config = buildTun2SocksConfig(socksServerPort = directSocksServer.port)
            val engineStartedSuccessfully = Tun2SocksBridge.start(engineFd, config)
            engineFd = -1 // Native now owns and closes this endpoint.
            if (!engineStartedSuccessfully) throw IOException("Unable to start TUN forwarding engine.")
            engineStarted = true
            ensureNotStopping()

            val totalLimitBytes = maxSizeMegabytes.coerceIn(1, 4 * 1024).toLong() * 1024L * 1024L
            val segmentLimitBytes = segmentSizeMegabytes.coerceIn(1, maxSizeMegabytes.coerceAtLeast(1)).toLong() * 1024L * 1024L
            val establishedSink = CapturePacketSink(captureFile, segmentLimitBytes)
            packetSink = establishedSink
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
            ensureNotStopping()

            val captureSession = CaptureSession(
                vpnInterface,
                establishedRelay,
                directSocksServer,
                establishedSink
            )
            session = captureSession
            vpnInterface = null
            relayInterface = null
            socksServer = null
            packetSink = null
            engineStarted = false

            synchronized(lifecycleLock) {
                activeSession = captureSession
                lifecycle = if (stopRequested.get()) {
                    CaptureLifecycle.Stopping
                } else {
                    CaptureLifecycle.Running
                }
            }
            ensureNotStopping()

            LiveCaptureStore.start(captureFile.absolutePath)
            captureStarted = true
            captureSession.startPumps()
            stopReason = waitForCaptureEnd(captureSession, maxDurationMinutes, totalLimitBytes, upstream.network)
        } catch (_: CaptureStoppedException) {
            // User initiated stop during setup. The finally block closes partial resources.
        } catch (error: Throwable) {
            failure = error
        } finally {
            if (engineFd >= 0) {
                closeOwnedFd(engineFd)
            }

            session?.close()
            session?.awaitPumps(PUMP_SHUTDOWN_TIMEOUT_MILLIS)
            session?.closeSink()
            if (session == null) {
                closeQuietly(vpnInterface)
                if (engineStarted) {
                    runCatching { Tun2SocksBridge.stop() }
                }
                closeQuietly(socksServer)
                closeQuietly(relayInterface)
                closeQuietly(packetSink)
            }

            synchronized(lifecycleLock) {
                if (activeSession === session) activeSession = null
                lifecycle = CaptureLifecycle.Idle
                captureThread = null
            }

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
                    if (failure != null) "failure" else stopReason
                )
                postCompletionNotification(LiveCaptureStore.state.value)
            }

            stopForegroundCompat()
            stopSelf()
        }
    }

    private fun writeCompletenessReport(
        outputFile: File,
        segmentFiles: List<File>,
        captureIpv6: Boolean,
        allowedApplications: List<String>,
        stopReason: String
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
        runCatching {
            File(outputFile.parentFile, "${outputFile.name}.report.json")
                .writeText(report.toString(2))
        }.onFailure { error ->
            LiveCaptureStore.recordIoError(error.message ?: "Unable to write capture completeness report.")
        }
    }

    private fun waitForCaptureEnd(
        session: CaptureSession,
        maxDurationMinutes: Int,
        sizeLimitBytes: Long,
        underlyingNetwork: Network?
    ): String {
        val startedAt = SystemClock.elapsedRealtime()
        val durationLimit = maxDurationMinutes.coerceIn(1, 24 * 60) * 60_000L
        val diagnosticAt = SystemClock.elapsedRealtime() + FORWARDING_DIAGNOSTIC_DELAY_MILLIS
        var diagnosticChecked = false
        while (session.isForwarding()) {
            if (underlyingNetwork != null) {
                // Upstream sockets are bound to this network for the entire capture.
                // Once the VPN becomes active, re-ranking all physical networks can
                // choose a different candidate even though this network is still up.
                val capabilities = getSystemService(ConnectivityManager::class.java)
                    .getNetworkCapabilities(underlyingNetwork)
                if (capabilities == null || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
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

    private fun postCompletionNotification(state: LiveCaptureState) {
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
        getSystemService(NotificationManager::class.java).notify(
            NOTIFICATION_ID + 1,
            NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(title)
                .setContentText(text)
                .setAutoCancel(true)
                .setContentIntent(contentIntent)
                .build()
        )
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
            if (captureThread == null) stopSelf()
            return
        }

        Thread(
            { session.close() },
            "LayerAnalyzer-VPN-Capture-Stop"
        ).also { it.start() }
    }

    private fun establishVpn(
        excludeSelf: Boolean,
        captureIpv6: Boolean,
        upstream: UnderlyingNetworkSnapshot,
        allowedApplications: List<String>
    ): ParcelFileDescriptor? {
        val scopedApplications = allowedApplications
            .filter { it.isNotBlank() && it != packageName }
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

    private fun createDirectSocksServer(underlyingNetwork: Network?): DirectSocks5Server {
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
            }
        )
    }

    private fun buildTun2SocksConfig(socksServerPort: Int): String = """
        tunnel:
          mtu: $TUN_MTU
        socks5:
          address: '127.0.0.1'
          port: $socksServerPort
          udp: 'udp'
        misc:
          connect-timeout: 10000
          tcp-read-write-timeout: 300000
          udp-read-write-timeout: 60000
          log-file: stderr
          log-level: warn
    """.trimIndent()

    private fun ensureNotStopping() {
        if (stopRequested.get()) throw CaptureStoppedException()
    }

    private fun buildNotification(): Notification {
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
            Intent(this, LiveCaptureVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(getString(R.string.capture_notification_title))
            .setContentText(getString(R.string.capture_notification_text))
            .setOngoing(true)
            .setContentIntent(contentIntent)
            .addAction(R.mipmap.ic_launcher, getString(R.string.capture_notification_stop), stopIntent)
            .build()
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
        private val sink: CapturePacketSink
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
                    writePacket(destination, buffer, length)
                    sink.record(buffer, length)
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
                runCatching { Tun2SocksBridge.stop() }
                closeQuietly(socksServer)
                closeQuietly(relayInterface)
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
        }

        private fun writeQueuedPackets() {
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
                    if (writerDrained) break
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

    companion object {
        const val ACTION_STOP = "com.example.layanalyzer.capture.STOP"
        const val EXTRA_EXCLUDE_SELF = "excludeSelf"
        const val EXTRA_CAPTURE_IPV6 = "captureIpv6"
        const val EXTRA_MAX_DURATION_MINUTES = "maxDurationMinutes"
        const val EXTRA_MAX_SIZE_MEGABYTES = "maxSizeMegabytes"
        const val EXTRA_SEGMENT_SIZE_MEGABYTES = "segmentSizeMegabytes"
        const val EXTRA_ALLOWED_APPLICATIONS = "allowedApplications"
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
