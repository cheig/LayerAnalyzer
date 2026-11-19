package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.tls.SocksNioTlsGateway
import com.example.layanalyzer.capture.tls.TlsGatewayChannel
import com.example.layanalyzer.capture.tls.TlsGatewayConnection
import com.example.layanalyzer.capture.tls.TlsRoutingPolicy
import com.example.layanalyzer.model.TlsCaptureSettings
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngineResult
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Real listener/selector, bounded DNS, native LAT1 hop, success writer and two-direction relay. */
class SocksNioGatewayIntegrationTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val literal = InetAddress.getByAddress(byteArrayOf(198.toByte(), 51, 100, 7))
    private val secondLiteral = InetAddress.getByAddress(byteArrayOf(203.toByte(), 0, 113, 8))
    private val auth = byteArrayOf(5, 1, 2, 1, 1, 'u'.code.toByte(), 1, 'p'.code.toByte())
    private val ready = frame("""{"version":1,"success":true,"errorCode":null}""")
    private val hello by lazy {
        val context = SSLContext.getInstance("TLS").apply { init(null, null, null) }
        val engine = context.createSSLEngine("asserted-sni.test", 443).apply {
            useClientMode = true
            sslParameters = sslParameters.apply { serverNames = listOf(SNIHostName("asserted-sni.test")) }
            beginHandshake()
        }
        val output = ByteBuffer.allocate(32 * 1024)
        assertEquals(SSLEngineResult.Status.OK, engine.wrap(ByteBuffer.allocate(0), output).status)
        output.flip()
        ByteArray(output.remaining()).also(output::get).also { assertEquals(22, it[0].toInt()) }
    }

    @Test fun readyThenPartialSuccessDrainThenPipelinedClientHelloAndReadySuffix() {
        val probe = ClientProbe(blockAfterBytes = 3)
        Fixture(clientIo = probe).use { fixture ->
            fixture.client(payload = hello, probe = probe).use { client -> fixture.accept().use { hop ->
                assertEquals(literal.hostAddress, metadata(hop).getString("destinationAddress"))
                assertNoData(client)
                assertNoData(hop)
                val download = "downstream-after-READY".toByteArray()
                hop.getOutputStream().write(ready + download)
                await { probe.zeroWrites.get() > 0 }
                assertArrayEquals(byteArrayOf(5, 0, 0), read(client, 3))
                assertReplyBarrier(fixture, probe)
                assertNoData(client)
                assertNoData(hop)
                probe.release.set(true)
                assertEquals(1, (byteArrayOf(5, 0, 0) + read(client, 7))[3].toInt())
                assertArrayEquals(download, read(client, download.size))
                assertArrayEquals(hello, read(hop, hello.size))
                await { fixture.server.stats().gatewayRelays == 1L }
                assertTrue(probe.replyDrained.get())
                assertEquals(1, fixture.gateway.channels.size)
                assertTrue(fixture.gateway.channels.single().isOpen)
                assertTrue(fixture.gateway.frames.all(::wiped))
            } }
        }
    }

    @Test fun alternatingZeroAndSingleByteWritesPreserveSuccessBeforeDownload() {
        val probe = ClientProbe(maxWrite = 1, alternatingZero = true)
        Fixture(clientIo = probe, gatewayIo = object : SocksNioGatewayConnect.GatewayIo {
            private val reads = AtomicInteger()
            override fun read(channel: SocketChannel, target: ByteBuffer): Int =
                if (reads.incrementAndGet() % 2 == 0) 0 else limited(target, 1) { channel.read(it) }
            override fun write(channel: SocketChannel, source: ByteBuffer): Int = limited(source, 3) { channel.write(it) }
        }).use { fixture ->
            fixture.client(payload = hello, probe = probe).use { client -> fixture.accept().use { hop ->
                metadata(hop)
                hop.getOutputStream().write(ready + byteArrayOf(42, 43, 44))
                assertEquals(0, reply(client)[1].toInt())
                assertArrayEquals(byteArrayOf(42, 43, 44), read(client, 3))
                assertArrayEquals(hello, read(hop, hello.size))
                assertTrue(probe.replyDrained.get())
                assertTrue(probe.zeroWrites.get() in 1..100)
            } }
        }
    }

    @Test fun clientWaitingForSuccessNeedsNoApplicationDataBeforeReady() {
        Fixture().use { fixture -> fixture.client().use { client -> fixture.accept().use { hop ->
            metadata(hop)
            assertNoData(hop)
            hop.getOutputStream().write(ready)
            assertEquals(0, reply(client)[1].toInt())
            client.getOutputStream().write(hello)
            assertArrayEquals(hello, read(hop, hello.size))
            hop.getOutputStream().write(byteArrayOf(9))
            assertArrayEquals(byteArrayOf(9), read(client, 1))
        } } }
    }

    @Test fun retainedPrefixAndUnreadClientTailUseSameIngressExactlyOnce() {
        val payload = hello + ByteArray(48 * 1024) { (it % 251).toByte() }
        val probe = ClientProbe(blockAfterBytes = 1)
        Fixture(clientIo = probe).use { fixture ->
            fixture.client(payload = payload, probe = probe).use { client -> fixture.accept().use { hop ->
                metadata(hop)
                hop.getOutputStream().write(ready)
                await { probe.zeroWrites.get() > 0 }
                assertArrayEquals(byteArrayOf(5), read(client, 1))
                assertReplyBarrier(fixture, probe)
                assertNoData(hop)
                probe.release.set(true)
                assertEquals(0, read(client, 9)[0].toInt())
                assertArrayEquals(payload, read(hop, payload.size))
                val response = ByteArray(48 * 1024) { (it % 239).toByte() }
                hop.getOutputStream().write(response)
                assertArrayEquals(response, read(client, response.size))
                assertTrue(fixture.server.stats().buffers!!.peakAllocatedBytes <= 2 * SocksTcpBufferBudget.MAX_DIRECTION_BYTES)
            } }
        }
    }

    @Test fun permanentlyZeroSuccessWriteTimesOutWithoutRelay() = replyFailure(ClientProbe(blockAfterBytes = 0), 0)
    @Test fun partiallyWrittenSuccessCannotRelayOnTimeout() = replyFailure(ClientProbe(blockAfterBytes = 1), 1)

    private fun replyFailure(probe: ClientProbe, prefix: Int) {
        Fixture(clientIo = probe).use { fixture ->
            fixture.client(payload = hello, probe = probe).use { client -> fixture.accept().use { hop ->
                metadata(hop)
                hop.getOutputStream().write(ready + byteArrayOf(55, 56))
                if (prefix > 0) assertArrayEquals(byteArrayOf(5), read(client, prefix))
                assertClosed(client)
                fixture.assertReleased()
                assertEquals(1L, fixture.server.stats().gateway!!.ready)
                assertEquals(0L, fixture.server.stats().gatewayRelays)
                assertEquals(0, probe.readAfterHandshake.get())
                assertTrue(probe.zeroWrites.get() in 1..1500)
                assertClosed(hop)
            } }
        }
    }

    @Test fun successWriteExceptionClosesBothChannelsAndPrefix() {
        val probe = ClientProbe(blockAfterBytes = 1, throwOnBlocked = true)
        Fixture(clientIo = probe).use { fixture ->
            fixture.client(payload = hello, probe = probe).use { client -> fixture.accept().use { hop ->
                metadata(hop)
                hop.getOutputStream().write(ready)
                assertArrayEquals(byteArrayOf(5), read(client, 1))
                assertEquals(-1, client.getInputStream().read())
                fixture.assertReleased()
                assertEquals(0L, fixture.server.stats().gatewayRelays)
                assertEquals(0, probe.readAfterHandshake.get())
                assertEquals(-1, hop.getInputStream().read())
            } }
        }
    }

    @Test fun domainLookupUsesFrozenWorkerAndFirstLiteralNotClientSni() {
        val names = CopyOnWriteArrayList<String>()
        val threads = CopyOnWriteArrayList<String>()
        Fixture(lookup = { names.add(it); threads.add(Thread.currentThread().name); arrayOf(literal, secondLiteral) }).use { fixture ->
            fixture.client(SocksDestination.Domain("original-destination.test"), hello).use { client -> fixture.accept().use { hop ->
                val metadata = metadata(hop)
                assertEquals(literal.hostAddress, metadata.getString("destinationAddress"))
                assertEquals(443, metadata.getInt("destinationPort"))
                assertEquals(7L, metadata.getLong("networkGeneration"))
                hop.getOutputStream().write(ready)
                assertEquals(0, reply(client)[1].toInt())
                assertArrayEquals(hello, read(hop, hello.size))
                assertEquals(listOf("original-destination.test"), names)
                assertTrue(threads.single().startsWith("SocksDns-"))
                assertEquals(0, fixture.directOpens.get())
            } }
        }
    }

    @Test fun failedDnsNeverCreatesMetadataHopOrDirectFallback() = dnsFailure { throw IOException("lookup") }
    @Test fun emptyDnsNeverCreatesMetadataHopOrDirectFallback() = dnsFailure { emptyArray() }
    @Test fun excessiveDnsAddressesNeverCreateMetadataHopOrDirectFallback() = dnsFailure {
        Array(SocksNioTcpConnect.MAX_ADDRESSES + 1) { literal }
    }

    private fun dnsFailure(lookup: (String) -> Array<InetAddress>) {
        Fixture(lookup = lookup).use { fixture ->
            fixture.client(SocksDestination.Domain("failed.test"), hello).use { assertFailure(it) }
            fixture.assertReleased()
            assertEquals(1L, fixture.server.stats().gateway!!.failures.getValue(SocksNioGatewayConnect.Stage.RESOLVING))
            fixture.assertNoDial()
        }
    }

    @Test fun dnsTimeoutDetachesSubscriberAndLateResultCannotCreateHop() {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        Fixture(lookup = { started.countDown(); release.await(); arrayOf(literal) }, dnsBudget = 100_000_000L).use { fixture ->
            try {
                fixture.client(SocksDestination.Domain("slow.test"), hello).use { client ->
                    assertTrue(started.await(3, TimeUnit.SECONDS))
                    assertFailure(client)
                    fixture.assertReleased()
                    assertEquals(1L, fixture.server.stats().gateway!!.timeouts)
                    assertEquals(1L, fixture.resolver.stats().timedOut)
                    assertEquals(0, fixture.resolver.stats().subscribers)
                    release.countDown()
                    await { fixture.resolver.stats().activeLookups == 0 }
                    fixture.assertNoDial()
                }
            } finally { release.countDown() }
        }
    }

    @Test fun dnsTimeIsNotRenewedWhenHopAndReadyBegin() {
        val offset = AtomicLong()
        Fixture(lookup = { offset.set(TimeUnit.SECONDS.toNanos(9)); arrayOf(literal) },
            gatewayIo = object : SocksNioGatewayConnect.GatewayIo {
                override fun read(channel: SocketChannel, target: ByteBuffer): Int {
                    // Advance on the owner in READY_READ; peer receipt can race LAT1 completion.
                    offset.set(TimeUnit.SECONDS.toNanos(11))
                    return channel.read(target)
                }
            },
            clock = { System.nanoTime() + offset.get() }, totalBudget = TimeUnit.SECONDS.toNanos(10)).use { fixture ->
            fixture.client(SocksDestination.Domain("deadline.test"), hello).use { client -> fixture.accept().use { hop ->
                metadata(hop)
                hop.getOutputStream().write(ready)
                assertFailure(client)
                fixture.assertReleased()
                val stats = fixture.server.stats().gateway!!
                assertEquals(1L, stats.timeouts)
                assertEquals(1L, stats.failures.getValue(SocksNioGatewayConnect.Stage.READY_READ))
                assertEquals(0L, stats.ready)
                assertEquals(0, fixture.directOpens.get())
            } }
        }
    }

    @Test fun dnsQueueFullFailsWithinBoundWithoutAReplacementWorker() = resolverLimit(false)
    @Test fun dnsSubscriberLimitFailsWithinBoundWithoutHop() = resolverLimit(true)

    private fun resolverLimit(subscriberLimit: Boolean) {
        val release = CountDownLatch(1)
        val started = CountDownLatch(1)
        val limits = SocksResolver.Limits(workers = 1, queuedQueries = 1,
            subscribers = if (subscriberLimit) 1 else 8, subscribersPerQuery = if (subscriberLimit) 1 else 8)
        Fixture(lookup = { started.countDown(); release.await(); arrayOf(literal) }, limits = limits).use { fixture ->
            val clients = ArrayList<Socket>()
            try {
                clients.add(fixture.client(SocksDestination.Domain("first.test")))
                assertTrue(started.await(3, TimeUnit.SECONDS))
                if (!subscriberLimit) {
                    clients.add(fixture.client(SocksDestination.Domain("second.test")))
                    await { fixture.resolver.stats().queuedQueries == 1 }
                }
                fixture.client(SocksDestination.Domain("rejected.test")).use { assertFailure(it) }
                assertEquals(1L, fixture.resolver.stats().rejected)
                assertEquals(1, fixture.resolver.stats().workers)
                fixture.assertNoDial()
                assertTrue(fixture.server.stop())
                fixture.assertStopped()
                assertEquals(0, fixture.resolver.stats().subscribers)
                clients.forEach { assertEquals(-1, it.getInputStream().read()) }
            } finally { release.countDown(); clients.forEach(Socket::close) }
        }
    }

    @Test fun stoppedDnsCannotContaminateRestartWithFreshNetworkScopeAndGateway() {
        val release = CountDownLatch(1)
        val started = CountDownLatch(1)
        Fixture(lookup = { started.countDown(); release.await(); arrayOf(literal) }).use { fixture ->
            try {
                fixture.client(SocksDestination.Domain("old.test"), hello).use { oldClient ->
                    assertTrue(started.await(3, TimeUnit.SECONDS))
                    val oldGateway = fixture.gateway
                    val oldGeneration = fixture.server.stats().server.captureGeneration
                    assertTrue(fixture.server.stop())
                    fixture.assertStopped()
                    assertEquals(-1, oldClient.getInputStream().read())
                    val freshGateway = fixture.newGateway(8)
                    fixture.restart(freshGateway, 8) { arrayOf(secondLiteral) }
                    assertTrue(fixture.server.stats().server.captureGeneration > oldGeneration)
                    assertFalse(fixture.server.invalidateNetwork(7))
                    fixture.client(SocksDestination.Domain("new.test"), hello).use { client -> fixture.accept().use { hop ->
                        val metadata = metadata(hop)
                        assertEquals(secondLiteral.hostAddress, metadata.getString("destinationAddress"))
                        assertEquals(8L, metadata.getLong("networkGeneration"))
                        hop.getOutputStream().write(ready)
                        assertEquals(0, reply(client)[1].toInt())
                        assertArrayEquals(hello, read(hop, hello.size))
                    } }
                    release.countDown()
                    await { fixture.resolver.stats().activeLookups == 0 }
                    assertEquals(0, oldGateway.descriptions.get())
                    assertTrue(oldGateway.closed.get())
                    assertEquals(0, fixture.directOpens.get())
                }
            } finally { release.countDown() }
        }
    }

    @Test fun candidateCannotBeReclassifiedAsDirectByExternalRoute() {
        Fixture(route = { SocksNioTcpServer.Route.DIRECT }).use { fixture ->
            fixture.client(SocksDestination.Domain("candidate.test"), hello).use { assertFailure(it) }
            fixture.assertReleased()
            fixture.assertNoDial()
            assertEquals(0L, fixture.resolver.stats().lookups)
            assertEquals(1L, fixture.server.stats().rejectedRoutes)
        }
    }

    @Test fun closedGatewayCannotTurnCandidateIntoDirectRoute() {
        Fixture().use { fixture ->
            fixture.gateway.close()
            fixture.client(SocksDestination.Domain("candidate.test"), hello).use { assertFailure(it) }
            fixture.assertReleased()
            fixture.assertNoDial()
        }
    }

    @Test fun gatewayRefusalDrainsFailureNotSuccessOrApplicationData() {
        Fixture().use { fixture -> fixture.client(payload = hello).use { client -> fixture.accept().use { hop ->
            metadata(hop)
            hop.getOutputStream().write(frame("""{"version":1,"success":false,"errorCode":"IO_ERROR"}"""))
            assertFailure(client, SocksProtocol.REPLY_HOST_UNREACHABLE)
            fixture.assertReleased()
            assertEquals(0L, fixture.server.stats().gatewayRelays)
            assertEquals(1L, fixture.server.stats().gateway!!.refusals)
            assertEquals(0, fixture.directOpens.get())
            assertEquals(-1, hop.getInputStream().read())
        } } }
    }

    @Test fun hopProtectionFailureWipesFrameAndNeverDialsDirect() {
        Fixture(prepare = { throw IOException("protect") }).use { fixture ->
            fixture.client(payload = hello).use { assertFailure(it) }
            fixture.assertReleased()
            assertEquals(1, fixture.gateway.channels.size)
            assertTrue(fixture.gateway.channels.none { it.isOpen })
            assertTrue(fixture.gateway.frames.all(::wiped))
            assertEquals(0, fixture.directOpens.get())
        }
    }

    @Test fun clientFinBeforeReadyStillDrainsPrefixAndOppositeDirection() {
        Fixture().use { fixture -> fixture.client(payload = hello).use { client -> fixture.accept().use { hop ->
            client.shutdownOutput()
            metadata(hop)
            hop.getOutputStream().write(ready)
            assertEquals(0, reply(client)[1].toInt())
            assertArrayEquals(hello, read(hop, hello.size))
            assertEquals(-1, hop.getInputStream().read())
            val response = "after-client-FIN".toByteArray()
            hop.getOutputStream().write(response)
            hop.shutdownOutput()
            assertArrayEquals(response, read(client, response.size))
            assertEquals(-1, client.getInputStream().read())
            fixture.assertReleased()
        } } }
    }

    @Test fun tlsGatewayAssemblyRejectsHigherInternalTcpProfiles() {
        Fixture().use { fixture ->
            listOf(SocksNioTcpProfile.TCP_128, SocksNioTcpProfile.TCP_256).forEach { profile ->
                SocksNioTcpServer(profile, fixture.resolver).use { server ->
                    val credentials = SocksCredentials.of("u", "p")
                    try {
                        assertThrows(IllegalArgumentException::class.java) {
                            server.start(SocksNioTcpServer.StartRequest(credentials, 7, { arrayOf(literal) }, {},
                                { SocksNioTcpServer.Route.TLS_GATEWAY }, fixture.gateway))
                        }
                    } finally { credentials.discard() }
                }
            }
            fixture.assertNoDial()
        }
    }

    @Test fun stopDuringSuccessRetryReturnsEveryLeaseBufferFrameAndTimer() = stopDuringReply(false)
    @Test fun networkInvalidationDuringSuccessRetryClosesOriginalHop() = stopDuringReply(true)

    /** Stages one bounded initial read so prefix retention is proven, not a TCP packetization guess. */
    private inner class ClientProbe(
        private val blockAfterBytes: Int = Int.MAX_VALUE,
        private val maxWrite: Int = Int.MAX_VALUE,
        private val alternatingZero: Boolean = false,
        private val throwOnBlocked: Boolean = false
    ) : SocksNioHandshake.ClientIo {
        val release = AtomicBoolean(false)
        val replyDrained = AtomicBoolean(false)
        val readAfterHandshake = AtomicInteger()
        val zeroWrites = AtomicInteger()
        private val replyBytes = AtomicInteger()
        private val writes = AtomicInteger()
        private var initial: ByteBuffer? = null
        private var delivered = false

        fun expect(bytes: Int) { initial = ByteBuffer.allocate(minOf(bytes, SocksNioHandshake.INPUT_BYTES)) }
        override fun read(channel: SocketChannel, target: ByteBuffer): Int {
            if (delivered) { readAfterHandshake.incrementAndGet(); return channel.read(target) }
            val staged = checkNotNull(initial)
            val count = channel.read(staged)
            if (count < 0) return count
            if (staged.hasRemaining()) return 0
            staged.flip()
            val total = staged.remaining()
            target.put(staged)
            delivered = true
            initial = null
            return total
        }
        override fun write(channel: SocketChannel, source: ByteBuffer): Int {
            if ((source.remaining() == 2 && replyBytes.get() == 0) || replyDrained.get()) return channel.write(source)
            if (!release.get() && replyBytes.get() >= blockAfterBytes) {
                if (throwOnBlocked) throw IOException("success write")
                zeroWrites.incrementAndGet()
                return 0
            }
            if (alternatingZero && writes.incrementAndGet() % 2 == 0) { zeroWrites.incrementAndGet(); return 0 }
            val allowed = if (release.get()) maxWrite else minOf(maxWrite, blockAfterBytes - replyBytes.get())
            val count = limited(source, allowed) { channel.write(it) }
            replyBytes.addAndGet(count)
            if (!source.hasRemaining()) replyDrained.set(true)
            return count
        }
    }

    private inner class TrackingGateway(port: Int, generation: Long, prepare: (Socket) -> Unit) : SocksNioTlsGateway {
        val channels = CopyOnWriteArrayList<SocketChannel>()
        val frames = CopyOnWriteArrayList<ByteBuffer>()
        val descriptions = AtomicInteger()
        val closed = AtomicBoolean()
        private val delegate = TlsGatewayChannel(port,
            "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU".toByteArray(), "capture-303", generation,
            TlsRoutingPolicy.freeze(TlsCaptureSettings(enabled = true, candidatePorts = setOf(443))),
            prepare, channelFactory = { SocketChannel.open().also(channels::add) })
        override fun route(destinationPort: Int) = delegate.route(destinationPort)
        override fun describe(destinationAddress: InetAddress, destinationPort: Int): TlsGatewayConnection {
            descriptions.incrementAndGet()
            return delegate.describe(destinationAddress, destinationPort).also { frames.add(it.frame.duplicate()) }
        }
        override fun close() { closed.set(true); delegate.close() }
    }

    private inner class Fixture(
        lookup: (String) -> Array<InetAddress> = { arrayOf(literal) },
        limits: SocksResolver.Limits = SocksResolver.Limits(),
        clientIo: SocksNioHandshake.ClientIo = SocksNioHandshake.ClientIo.CHANNEL,
        gatewayIo: SocksNioGatewayConnect.GatewayIo = SocksNioGatewayConnect.GatewayIo.CHANNEL,
        clock: () -> Long = System::nanoTime,
        totalBudget: Long = SocksNioGatewayConnect.ESTABLISHMENT_TIMEOUT_NANOS,
        dnsBudget: Long = SocksNioTcpResolve.DNS_TIMEOUT_NANOS,
        prepare: (Socket) -> Unit = {},
        private val route: (SocksRequest) -> SocksNioTcpServer.Route = { SocksNioTcpServer.Route.TLS_GATEWAY }
    ) : AutoCloseable {
        val resolver = SocksResolver.forTest(limits)
        private val listener = ServerSocket(0, 64, loopback).apply { soTimeout = 5000 }
        private val gateways = CopyOnWriteArrayList<TrackingGateway>()
        var gateway = TrackingGateway(listener.localPort, 7, prepare).also(gateways::add)
        val directOpens = AtomicInteger()
        val server = SocksNioTcpServer(SocksNioTcpProfile.TCP_64, resolver,
            connectIo = object : SocksNioTcpConnect.ConnectIo {
                override fun open() = SocketChannel.open().also { directOpens.incrementAndGet() }
            }, gatewayIo = gatewayIo, clientIo = clientIo, sessionNanoClock = clock,
            gatewayEstablishmentTimeoutNanos = totalBudget, gatewayDnsTimeoutNanos = dnsBudget)
        private var port = start(gateway, 7, lookup)

        private fun start(selected: TrackingGateway, generation: Long, lookup: (String) -> Array<InetAddress>): Int =
            server.start(SocksNioTcpServer.StartRequest(SocksCredentials.of("u", "p"), generation,
                lookup, {}, route, selected))
        fun newGateway(generation: Long) = TrackingGateway(listener.localPort, generation, {}).also(gateways::add)
        fun restart(selected: TrackingGateway, generation: Long, lookup: (String) -> Array<InetAddress>) {
            gateway = selected
            port = start(selected, generation, lookup)
        }
        fun accept(): Socket = listener.accept().apply { soTimeout = 5000 }
        fun client(destination: SocksDestination = SocksDestination.Ip(literal), payload: ByteArray = byteArrayOf(),
            probe: ClientProbe? = null): Socket = Socket().also {
            val bytes = auth + SocksProtocol.encodeRequest(SocksRequest(1, destination, 443)) + payload
            probe?.expect(bytes.size)
            it.soTimeout = 5000
            it.connect(InetSocketAddress(loopback, port))
            it.getOutputStream().write(bytes)
            assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(it, 4))
        }
        fun assertNoDial() {
            assertEquals(0, directOpens.get())
            assertEquals(0, gateway.descriptions.get())
            assertEquals(0, gateway.channels.size)
        }
        fun assertReleased() {
            await { server.stats().server.admission!!.tcp.current == 0 && server.stats().buffers!!.reservedBytes == 0 }
            val stats = server.stats()
            assertEquals(0, stats.buffers!!.allocatedBytes)
            assertEquals(0, stats.server.admission!!.udp.current)
            assertEquals(0, stats.server.admission.handshakes.current)
            assertEquals(listOf(0, 0), stats.server.admission.ownerLoads)
            assertEquals(0, stats.server.admission.pendingReservations)
            assertEquals(0, stats.runResolver!!.subscribers)
            gateways.forEach { gateway ->
                assertTrue(gateway.frames.all(::wiped))
                assertTrue(gateway.channels.none { it.isOpen })
            }
        }
        fun assertStopped() {
            await { server.stats().eventLoopThreadsAlive == 0 }
            assertReleased()
            val stats = server.stats()
            assertEquals(SocksNioServer.State.STOPPED, stats.server.state)
            assertFalse(stats.runResolver!!.open)
            assertTrue(gateways.all { it.closed.get() })
            stats.server.loops.forEach {
                assertEquals(0, it.channels); assertEquals(0, it.keys); assertEquals(0, it.resources)
                assertEquals(0, it.timers); assertEquals(0, it.commands); assertEquals(0, it.completions)
                assertEquals(0L, it.cleanupFailures)
            }
        }
        override fun close() {
            try { assertTrue(server.stop()); assertStopped() }
            finally { listener.close(); assertTrue(resolver.shutdownForTest()) }
        }
    }

    private fun assertReplyBarrier(fixture: Fixture, probe: ClientProbe) {
        val stats = fixture.server.stats()
        assertEquals(1L, stats.gateway!!.ready)
        assertEquals(0L, stats.gatewayRelays)
        assertEquals(0L, stats.connectedRelays)
        assertEquals(0, stats.buffers!!.allocatedBytes)
        assertEquals(2 * SocksTcpBufferBudget.MAX_DIRECTION_BYTES, stats.buffers.reservedBytes)
        assertEquals(0, probe.readAfterHandshake.get())
        assertFalse(probe.replyDrained.get())
        assertTrue(fixture.gateway.frames.all(::wiped))
    }
    private fun metadata(hop: Socket): JSONObject {
        val header = ByteBuffer.wrap(read(hop, 8))
        assertEquals(TlsGatewayChannel.FRAME_MAGIC_INT, header.int)
        val length = header.int
        assertTrue(length in 1..TlsGatewayChannel.MAX_HEADER_BYTES)
        return JSONObject(String(read(hop, length), Charsets.UTF_8))
    }
    private fun frame(json: String): ByteArray {
        val bytes = json.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(8 + bytes.size).putInt(TlsGatewayChannel.FRAME_MAGIC_INT).putInt(bytes.size).put(bytes).array()
    }
    private fun reply(socket: Socket): ByteArray {
        val header = read(socket, 4)
        assertEquals(5, header[0].toInt())
        assertEquals(0, header[2].toInt())
        assertTrue(header[3].toInt() in listOf(1, 4))
        return header + read(socket, if (header[3].toInt() == 1) 6 else 18)
    }
    private fun assertFailure(socket: Socket, code: Int = SocksProtocol.REPLY_GENERAL_FAILURE) {
        assertArrayEquals(SocksProtocol.encodeReply(code), reply(socket))
        assertEquals(-1, socket.getInputStream().read())
    }
    private fun read(socket: Socket, size: Int): ByteArray {
        val bytes = ByteArray(size)
        var offset = 0
        while (offset < size) {
            val count = socket.getInputStream().read(bytes, offset, size - offset)
            assertTrue("early EOF at $offset/$size", count > 0)
            offset += count
        }
        return bytes
    }
    private fun assertNoData(socket: Socket) {
        val timeout = socket.soTimeout
        socket.soTimeout = 60
        try { assertThrows(SocketTimeoutException::class.java) { socket.getInputStream().read() } }
        finally { socket.soTimeout = timeout }
    }
    private fun limited(buffer: ByteBuffer, count: Int, operation: (ByteBuffer) -> Int): Int {
        val oldLimit = buffer.limit()
        buffer.limit(buffer.position() + minOf(count, buffer.remaining()))
        return try { operation(buffer) } finally { buffer.limit(oldLimit) }
    }
    private fun wiped(buffer: ByteBuffer): Boolean = buffer.duplicate().apply { clear() }.let {
        while (it.hasRemaining()) if (it.get().toInt() != 0) return false
        true
    }
    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!condition()) { assertTrue("condition deadline", System.nanoTime() < deadline); Thread.sleep(2) }
    }

    private fun stopDuringReply(invalidate: Boolean) {
        val probe = ClientProbe(blockAfterBytes = 1)
        Fixture(clientIo = probe).use { fixture ->
            fixture.client(payload = hello, probe = probe).use { client -> fixture.accept().use { hop ->
                metadata(hop)
                hop.getOutputStream().write(ready + byteArrayOf(88))
                await { probe.zeroWrites.get() > 0 }
                read(client, 1)
                assertReplyBarrier(fixture, probe)
                if (invalidate) {
                    assertFalse(fixture.server.invalidateNetwork(6))
                    assertTrue(fixture.server.invalidateNetwork(7))
                } else assertTrue(fixture.server.stop())
                fixture.assertStopped()
                assertClosed(client)
                assertClosed(hop)
                assertEquals(0, probe.readAfterHandshake.get())
            } }
        }
    }

    private fun assertClosed(socket: Socket) {
        try { assertEquals(-1, socket.getInputStream().read()) }
        catch (error: java.net.SocketException) {
            // Forced teardown with unread pipelined bytes can produce RST on
            // Android/Linux. Neither application data nor timeout is accepted.
            assertTrue(error.toString(), error.message.orEmpty().contains("reset", ignoreCase = true))
        }
    }
}
