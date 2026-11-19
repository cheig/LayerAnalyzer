package com.example.layanalyzer.capture.socks

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.net.http.X509TrustManagerExtensions
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.Os
import android.system.ErrnoException
import android.system.OsConstants
import android.system.StructPollfd
import com.example.layanalyzer.BuildConfig
import com.example.layanalyzer.capture.RawPcapWriter
import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.Tun2SocksBridge
import com.example.layanalyzer.capture.tls.AndroidTlsWrappingKeyProvider
import com.example.layanalyzer.capture.tls.AndroidUpstreamTrustVerifier
import com.example.layanalyzer.capture.tls.SocksNioTlsGateway
import com.example.layanalyzer.capture.tls.TlsCaptureCoordinator
import com.example.layanalyzer.capture.tls.TlsCaptureStart
import com.example.layanalyzer.capture.tls.TlsCaptureState
import com.example.layanalyzer.capture.tls.TlsCertificateManager
import com.example.layanalyzer.capture.tls.TlsNetworkAccess
import com.example.layanalyzer.capture.tls.TlsSecretStore
import com.example.layanalyzer.capture.tls.TlsUpstreamVerification
import com.example.layanalyzer.capture.tls.UpstreamSocketProtector
import com.example.layanalyzer.model.TlsCaptureSettings
import java.io.File
import java.io.FileDescriptor
import java.net.InetAddress
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class SocksNioFixtureVpnService : VpnService() {
    inner class FixtureBinder : Binder() {
        val service: SocksNioFixtureVpnService get() = this@SocksNioFixtureVpnService
    }

    internal data class Capture(
        val captureId: String,
        val pcap: File,
        val proxyRoot: ByteArray,
        val secrets: TlsSecretStore
    )

    private val live = AtomicBoolean(false)
    private val pumpFailure = AtomicReference<Throwable?>()
    private val watchdog = Executors.newSingleThreadScheduledExecutor()
    private val pumps = ArrayList<Thread>()
    private var coordinator: TlsCaptureCoordinator? = null
    private var server: SocksNioTcpServer? = null
    private var stoppedNioStats: SocksNioTcpServer.Stats? = null
    private var tun: ParcelFileDescriptor? = null
    private var relay: ParcelFileDescriptor? = null
    private var writer: RawPcapWriter? = null
    private var hevStarted = false
    private var used = false
    private var bytesWritten = 0L
    private var packetsWritten = 0
    private var timeout: ScheduledFuture<*>? = null
    private val drainMonitor = Object()
    private val idlePolls = IntArray(2)
    private var clientFin = false
    private var serverFin = false

    override fun onBind(intent: Intent): IBinder? =
        if (intent.action == FIXTURE_ACTION) FixtureBinder() else super.onBind(intent)

    internal val fixtureStopped: Boolean get() = !live.get() && tun == null && relay == null &&
        !Tun2SocksBridge.isRunning() && pumps.none { it.isAlive } && coordinator == null && server == null

    internal fun nioStats() = server?.stats() ?: stoppedNioStats

    @Synchronized
    internal fun startFixture(host: String, port: Int, rootDer: ByteArray): Capture {
        check(BuildConfig.DEBUG && BuildConfig.TLS_ENABLED && !BuildConfig.TLS_PROBE_ENABLED)
        check(Build.VERSION.SDK_INT == 36) { "NIO-305 requires API36; no substitute device" }
        check(!used && !Tun2SocksBridge.isRunning())
        check(prepare(this) == null) { "Explicit VPN consent required before fixture" }
        require(host.matches(Regex("[0-9.]+")) && port in 1..65535)
        val address = InetAddress.getByName(host)
        require(address.address.size == 4 && address.isSiteLocalAddress && !address.isLoopbackAddress)
        require(rootDer.size in 1..16384)
        used = true
        try {
            val manager = getSystemService(ConnectivityManager::class.java)
            check(manager.allNetworks.none {
                manager.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }) { "An existing VPN must not be replaced" }
            val network = manager.activeNetwork?.takeIf {
                manager.getNetworkCapabilities(it)?.let { caps ->
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                } == true
            } ?: error("A controlled physical network is required")
            val snapshot = AtomicReference(UpstreamSocketProtector.NetworkSnapshot(network, SystemClock.elapsedRealtimeNanos()))
            val access = object : TlsNetworkAccess {
                override val generation = checkNotNull(snapshot.get()).generation
                override val upstream = UpstreamSocketProtector({ snapshot.get() }, { protect(it) })
                override fun prepareHopSocket(socket: Socket) { check(protect(socket)) }
                override fun close() { snapshot.set(null) }
            }
            val captureId = UUID.randomUUID().toString()
            val directory = File(noBackupFilesDir, "socks-nio-305/$captureId").apply { check(mkdirs()) }
            val keys = AndroidTlsWrappingKeyProvider("layeranalyzer.nio305.$captureId")
            val certificates = TlsCertificateManager(directory, keys)
            val secrets = TlsSecretStore(directory, keys)
            val trustStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null)
                setCertificateEntry("fixture", CertificateFactory.getInstance("X.509").generateCertificate(rootDer.inputStream()))
            }
            val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trustStore) }
                .trustManagers.filterIsInstance<X509TrustManager>().single()
            val extension = X509TrustManagerExtensions(trust)
            val verifier = AndroidUpstreamTrustVerifier { chain, authType, identity ->
                extension.checkServerTrusted(chain, authType, identity)
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel("nio305", "NIO-305 bounded fixture", NotificationManager.IMPORTANCE_LOW))
            startForeground(305, Notification.Builder(this, "nio305")
                .setSmallIcon(android.R.drawable.stat_sys_warning).setContentTitle("NIO-305 test fixture")
                .setContentText("Test-owned VPN; stops within 60 seconds").build())
            val tls = TlsCaptureCoordinator(captureId,
                TlsCaptureSettings(enabled = true, candidatePorts = setOf(port), includeHosts = listOf("upstream.fixture.test")),
                listOf(packageName), access, { certificates }, { secrets },
                verification = TlsUpstreamVerification(verifier::verifyUpstream))
            coordinator = tls
            val started = tls.start() as? TlsCaptureStart.Started ?: error("Real TLS engine failed to start")
            val credentials = SocksCredentials.generate()
            val nio = SocksNioTcpServer(SocksNioTcpProfile.TCP_64).also { server = it }
            val socksPort = nio.start(SocksNioTcpServer.StartRequest(credentials, access.generation,
                { error("Numeric fixture destination must not resolve DNS") },
                { error("Direct upstream forbidden in NIO-305 fixture") },
                { if (it.port == port) SocksNioTcpServer.Route.TLS_GATEWAY else SocksNioTcpServer.Route.REJECT },
                started.gateway as SocksNioTlsGateway))
            val pair = checkNotNull(Tun2SocksBridge.createPacketSocketPair())
            if (pair.size != 2) {
                pair.forEach { fd -> runCatching { ParcelFileDescriptor.adoptFd(fd).close() } }
                error("Invalid packet socket pair")
            }
            var ownedEngineFd = pair[1]
            try {
                relay = ParcelFileDescriptor.adoptFd(pair[0])
                val config = """
                    tunnel:
                      mtu: 1500
                    socks5:
                      address: '127.0.0.1'
                      port: $socksPort
                      username: '${credentials.username}'
                      password: '${credentials.password}'
                    misc:
                      connect-timeout: 10000
                      tcp-read-write-timeout: 15000
                      log-file: stderr
                      log-level: warn
                """.trimIndent()
                val consumedFd = ownedEngineFd
                ownedEngineFd = -1
                hevStarted = Tun2SocksBridge.start(consumedFd, config)
            } finally {
                if (ownedEngineFd >= 0) ParcelFileDescriptor.adoptFd(ownedEngineFd).close()
            }
            check(hevStarted)
            val pcap = File(directory, "tun.pcap")
            writer = RawPcapWriter(pcap.outputStream()).also { it.writeHeader() }
            tun = checkNotNull(Builder().setSession("NIO-305 fixture").setMtu(1500)
                .addAddress("10.77.0.2", 32).addRoute(host, 32).addAllowedApplication(packageName)
                .setUnderlyingNetworks(arrayOf(network)).setBlocking(false).establish())
            live.set(true)
            pump(checkNotNull(tun).fileDescriptor, checkNotNull(relay).fileDescriptor)
            pump(checkNotNull(relay).fileDescriptor, checkNotNull(tun).fileDescriptor)
            timeout = watchdog.schedule({ try { stopFixture() } finally { stopSelf() } }, 60, TimeUnit.SECONDS)
            return Capture(captureId, pcap, certificates.exportPublicCertificate().certificateDer,
                secrets)
        } catch (failure: Throwable) {
            try { stopFixture() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
            throw failure
        }
    }

    internal fun awaitPacketDrain() {
        val deadline = SystemClock.elapsedRealtime() + 3000
        synchronized(drainMonitor) {
            while (true) {
                check(live.get() && pumpFailure.get() == null) { "Fixture stopped before packet drain" }
                val admission = server?.stats()?.server?.admission
                if (admission?.tcp?.current == 0 && clientFin && serverFin && idlePolls.all { it > 0 }) return
                val remaining = deadline - SystemClock.elapsedRealtime()
                check(remaining > 0) { "TCP close and TUN packet drain timed out" }
                drainMonitor.wait(minOf(remaining, 200))
            }
        }
    }

    private fun pump(input: FileDescriptor, output: FileDescriptor) {
        val direction = pumps.size
        val thread = Thread({
            try {
                val bytes = ByteArray(65535)
                val poll = StructPollfd().apply { fd = input; events = OsConstants.POLLIN.toShort() }
                while (live.get()) {
                    if (Os.poll(arrayOf(poll), 200) == 0) {
                        synchronized(drainMonitor) { idlePolls[direction]++; drainMonitor.notifyAll() }
                        continue
                    }
                    check(poll.revents.toInt() and OsConstants.POLLIN != 0)
                    val length = try { Os.read(input, bytes, 0, bytes.size) } catch (error: ErrnoException) {
                        if (error.errno == OsConstants.EAGAIN) continue else throw error
                    }
                    check(length > 0)
                    synchronized(drainMonitor) {
                        idlePolls[direction] = 0
                        val header = (bytes[0].toInt() and 15) * 4
                        if (length > header + 13 && bytes[9].toInt() == 6 && bytes[header + 13].toInt() and 1 != 0) {
                            if (direction == 0) clientFin = true else serverFin = true
                        }
                        drainMonitor.notifyAll()
                    }
                    synchronized(checkNotNull(writer)) {
                        bytesWritten += length
                        packetsWritten++
                        check(bytesWritten <= 4 * 1024 * 1024 && packetsWritten <= 8192)
                        writer?.writePacket(System.currentTimeMillis(), bytes, length)
                    }
                    val deadline = SystemClock.elapsedRealtime() + 2000
                    val writable = StructPollfd().apply { fd = output; events = OsConstants.POLLOUT.toShort() }
                    while (live.get()) {
                        check(SystemClock.elapsedRealtime() < deadline) { "Packet output timeout" }
                        if (Os.poll(arrayOf(writable), 200) == 0) continue
                        check(writable.revents.toInt() and OsConstants.POLLOUT != 0)
                        try {
                            check(Os.write(output, bytes, 0, length) == length)
                            break
                        } catch (error: ErrnoException) {
                            if (error.errno != OsConstants.EAGAIN) throw error
                        }
                    }
                }
            } catch (failure: Throwable) {
                if (live.get() && pumpFailure.compareAndSet(null, failure)) {
                    watchdog.execute { try { stopFixture() } finally { stopSelf() } }
                }
            }
        }, "nio305-pump-${pumps.size}").apply { isDaemon = true }
        pumps.add(thread)
        thread.start()
    }

    @Synchronized
    internal fun stopFixture(): TlsCaptureState? {
        live.set(false)
        timeout?.cancel(false)
        timeout = null
        var failure = pumpFailure.getAndSet(null)
        fun release(operation: () -> Unit) {
            try { operation() } catch (cleanup: Throwable) {
                if (failure == null) failure = cleanup else failure?.addSuppressed(cleanup)
            }
        }
        val oldTun = tun
        tun = null
        release { oldTun?.close() }
        val nio = server
        server = null
        release { check(nio?.stop() != false) }
        if (nio != null) stoppedNioStats = nio.stats()
        if (hevStarted) { release { Tun2SocksBridge.stop() }; hevStarted = false }
        val oldRelay = relay
        relay = null
        release { oldRelay?.close() }
        pumps.forEach { thread -> release { thread.join(1500) } }
        release { check(pumps.none { it.isAlive }) { "Fixture pumps did not stop within budget" } }
        val oldWriter = writer
        writer = null
        release { oldWriter?.close() }
        val oldCoordinator = coordinator
        coordinator = null
        var state: TlsCaptureState? = null
        release { state = oldCoordinator?.stop() }
        release { stopForeground(STOP_FOREGROUND_REMOVE) }
        release { check(fixtureStopped) { "Fixture VPN/HEV is not fully stopped" } }
        failure?.let { throw it }
        return state
    }

    override fun onRevoke() { try { stopFixture() } finally { super.onRevoke() } }
    override fun onDestroy() {
        try { stopFixture() } finally { watchdog.shutdownNow(); super.onDestroy() }
    }

    companion object {
        const val FIXTURE_ACTION = "com.example.layanalyzer.NIO305_FIXTURE"
    }
}
