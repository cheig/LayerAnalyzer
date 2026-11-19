// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.SocksSessionLimits
import com.example.layanalyzer.capture.SocksUdpRequest
import com.example.layanalyzer.capture.UdpDestinationPolicy
import com.example.layanalyzer.capture.UdpVerdict
import com.example.layanalyzer.capture.tls.TlsGatewayChannel
import com.example.layanalyzer.capture.tls.TlsRoutingPolicy
import com.example.layanalyzer.model.TlsCaptureSettings
import java.io.DataInputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.ServerSocketChannel
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.*
import org.junit.Test

/** Actual SOCKS/Selector/loopback. The test thread drives endpoints, with no echo worker/peer. */
class SocksNioUdpServerTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val auth = byteArrayOf(5, 1, 2, 1, 1, 'u'.code.toByte(), 1, 'p'.code.toByte())

    @Test fun udp64AndTcp64ShareOwnersTransferAndRecoverAtCapacity() = capacity(SocksNioUdpProfile.UDP_64)
    @Test fun udp128AndTcp64ShareOwnersTransferAndRecoverAtCapacity() = capacity(SocksNioUdpProfile.UDP_128)
    @Test fun udp256AndTcp64ShareOwnersTransferAndRecoverAtCapacity() = capacity(SocksNioUdpProfile.UDP_256)

    private fun capacity(profile: SocksNioUdpProfile) {
        Fixture(profile).use { f -> endpoint().use { target -> tcpEndpoint().use { tcpTarget ->
            val udp = ArrayList<Link>()
            val tcp = ArrayList<Socket>()
            val peers = ArrayList<Socket>()
            try {
                repeat(profile.udp) { index ->
                    udp.add(f.link().also { roundTrip(it, target, payload(index, 257)) })
                }
                await { f.server.stats().udp!!.associations == profile.udp }
                val threadIds = f.workers.map { it.id }
                assertEquals(2, threadIds.size)
                assertEquals(2, f.server.stats().eventLoopThreadsAlive)
                // Keep ALL controls alive and transfer a second distinct packet on every association.
                udp.forEachIndexed { index, link -> roundTrip(link, target, payload(index + 71, 513)) }
                f.client(3, 0).use { overflow ->
                    assertEquals(1, reply(overflow)[1].toInt())
                    assertEquals(-1, overflow.getInputStream().read())
                }
                await { f.server.stats().server.admission!!.rejectedUdp == 1L }
                // UDP is full; the same listener/group/admission still accepts all 64 TCP slots.
                repeat(64) { index ->
                    val client = f.client(1, tcpTarget.localPort)
                    tcp.add(client)
                    val peer = tcpTarget.accept().apply { soTimeout = 3000 }
                    peers.add(peer)
                    assertEquals(0, reply(client)[1].toInt())
                    exchangeTcp(client, peer, payload(index, 43))
                }
                f.client(1, tcpTarget.localPort).use { overflow ->
                    assertEquals(1, reply(overflow)[1].toInt())
                    assertEquals(-1, overflow.getInputStream().read())
                }
                await { f.server.stats().server.admission!!.rejectedTcp == 1L }
                udp.removeAt(0).close()
                await { f.server.stats().udp!!.associations == profile.udp - 1 }
                // TCP is full; a released UDP slot recovers on the SAME service and owners.
                udp.add(f.link().also { roundTrip(it, target, payload(999, 1025)) })
                await { f.server.stats().udp!!.associations == profile.udp }
                // Timer expiry temporarily removes its node before the owner rearms it. Capture
                // a settled snapshot rather than treating that legal callback window as a leak.
                var settled = f.server.stats()
                await {
                    settled = f.server.stats()
                    settled.udp!!.queuedBytes == 0 && settled.server.admission!!.handshakes.current == 0 &&
                        settled.server.loops.sumOf { it.timers } == profile.udp
                }
                val full = settled
                assertEquals(profile, full.udpProfile)
                assertTrue(full.supportsUdp)
                assertEquals(64, full.server.admission!!.tcp.current)
                assertEquals(profile.udp, full.server.admission.udp.current)
                assertEquals(profile.udp, full.server.admission.udp.limit)
                assertEquals(2, full.udp!!.scratchBuffers)
                assertEquals(2 * 65535, full.udp.scratchBytes)
                assertEquals(0, full.udp.queuedBytes)
                assertEquals(3 * profile.udp + 2 * 64 + 1, full.server.loops.sumOf { it.channels })
                assertEquals(profile.udp + 64 + 1, full.server.loops.sumOf { it.resources })
                assertEquals(profile.udp, full.server.loops.sumOf { it.timers })
                assertEquals(0, full.processResolver.workers)
                assertEquals(0L, full.processResolver.lookups)
                assertEquals(0L, full.udp.queueDroppedPackets)
                assertEquals(0L, full.udp.sendFailures)
                assertEquals(threadIds, f.workers.map { it.id })
                // TCP also recovers while UDP remains full.
                tcp.removeAt(0).close(); peers.removeAt(0).close()
                await { f.server.stats().server.admission!!.tcp.current == 63 }
                f.client(1, tcpTarget.localPort).use { replacement -> tcpTarget.accept().use { peer ->
                    peer.soTimeout = 3000
                    assertEquals(0, reply(replacement)[1].toInt())
                    exchangeTcp(replacement, peer, payload(7, 321))
                } }
                val beforeStop = System.nanoTime()
                assertTrue(f.server.stop())
                val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - beforeStop)
                assertTrue("full stop $elapsed ms", elapsed < 2000)
                assertClean(f.server)
                println("P4 capacity UDP=${profile.udp} TCP=64 owners=2 DNS=0 stopMs=$elapsed")
            } finally { udp.forEach { it.close() }; tcp.forEach { it.close() }; peers.forEach { it.close() } }
        } } }
    }

    @Test fun finiteMixedProfilesRequireExplicitPreparationAndKeepLegacyAndTlsLimits() {
        assertEquals(listOf(64, 128, 256), SocksNioUdpProfile.entries.map { it.udp })
        assertEquals(64, SocksSessionLimits().udp)
        assertThrows(IllegalArgumentException::class.java) { SocksSessionLimits(udp = 128) }
        SocksNioUdpProfile.entries.forEach { profile ->
            val config = profile.eventLoopConfig()
            assertEquals(64 + 64 + profile.udp + 1, config.resourceCapacity)
            assertEquals(64 + 128 + 3 * profile.udp + 1, config.channelCapacity)
            assertEquals(128 + 256 + 3 * profile.udp, config.timerCapacity)
            assertThrows(IllegalArgumentException::class.java) { config.copy(resourceCapacity = config.resourceCapacity + 1) }
            assertThrows(IllegalArgumentException::class.java) { config.copy(channelCapacity = config.channelCapacity + 1) }
            assertThrows(IllegalArgumentException::class.java) { config.copy(timerCapacity = config.timerCapacity + 1) }
            assertThrows(IllegalArgumentException::class.java) { config.copy(tcpValidationProfile = SocksNioTcpProfile.TCP_64) }
            assertThrows(IllegalArgumentException::class.java) {
                SocksEventLoopGroup(config, sessionLimits = SocksSessionLimits(udp = 32))
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            SocksNioTcpServer(SocksNioTcpProfile.TCP_128, udpProfile = SocksNioUdpProfile.UDP_64)
        }
        val server = SocksNioTcpServer(SocksNioTcpProfile.TCP_64, udpProfile = SocksNioUdpProfile.UDP_64)
        assertThrows(IllegalArgumentException::class.java) { server.start(request().copy(prepareUdp = null)) }
        assertEquals(SocksNioServer.State.NEW, server.stats().server.state)
    }

    @Test fun assembledDomainLargeEmptyPacketsAndEndpointAllowlistKeepExactBytesAndCounts() {
        val lookups = AtomicInteger()
        Fixture(startRequest = request(lookup = { lookups.incrementAndGet(); arrayOf(loopback) })).use { f ->
            endpoint().use { target -> endpoint().use { rogue -> f.link().use { link ->
                val large = payload(19, 65_497)
                roundTrip(link, target, large)
                roundTrip(link, target, byteArrayOf())
                roundTrip(link, target, payload(9, 155), SocksDestination.Domain("assembly.test"))
                assertEquals(1, lookups.get())
                val valid = payload(20, 77)
                link.send(target.localPort, valid)
                val received = receive(target)
                assertArrayEquals(valid, received.payload())
                val encoded = wire(target.localPort, byteArrayOf(44))
                rogue.send(DatagramPacket(encoded, encoded.size, link.relay))
                rogue.send(DatagramPacket(byteArrayOf(55), 1, received.socketAddress))
                await {
                    val traffic = f.server.stats().udp!!.traffic
                    traffic.sourceRejectedDatagrams == 1L && traffic.unallowedResponses == 1L
                }
                target.send(DatagramPacket(valid, valid.size, received.socketAddress))
                assertArrayEquals(valid, link.response())
                noPacket(link.client)
                val bytes = (65_497 + 155 + 77).toLong()
                await { f.server.stats().udp!!.traffic.sentBytes == bytes && f.server.stats().udp!!.traffic.receivedBytes == bytes }
                assertEquals(1L, f.server.stats().udp!!.ambiguousEmptySends)
                link.control.close()
                await { f.server.stats().udp!!.associations == 0 }
                assertEquals(bytes, f.server.stats().udp!!.traffic.sentBytes)
                assertEquals(0, f.server.stats().udp!!.scratchBytes)
            } } }
        }
    }

    @Test fun assembledUdp443PolicyIsFrozenAndAppliesAfterDomainResolution() {
        val address = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 10))
        DatagramSocket(InetSocketAddress(address, 0)).use { target ->
            target.soTimeout = 3000
            Fixture().use { f -> f.link().use { roundTrip(it, target, payload(1, 39), SocksDestination.Ip(address)) } }
            val rule = UdpDestinationPolicy { _, port ->
                if (port == 443) UdpVerdict.BlockSelectedUdp443 else UdpVerdict.Forward
            }
            val sends = AtomicInteger()
            val io = object : UdpDataPlane.ChannelIo {
                override fun send(channel: DatagramChannel, bytes: ByteBuffer, target: InetSocketAddress): Int {
                    sends.incrementAndGet()
                    return super.send(channel, bytes, target)
                }
            }
            Fixture(startRequest = request(lookup = { arrayOf(address) }).copy(udpPolicy = rule), io = io).use { f ->
                f.link().use { link ->
                    link.send(443, payload(2, 49), SocksDestination.Domain("blocked.test"))
                    await { f.server.stats().udp!!.traffic.blockedDatagrams == 1L }
                    assertEquals(49L, f.server.stats().udp!!.traffic.blockedBytes)
                    assertEquals(0L, f.server.stats().udp!!.traffic.sentBytes)
                    assertEquals(0L, f.server.stats().udp!!.queueDroppedPackets)
                    assertEquals(0L, f.server.stats().udp!!.sendFailures)
                    // The blocked port stays 443. Observe the actual syscall
                    // boundary without requiring privileged UDP binds on Android.
                    assertEquals(0, sends.get())
                }
            }
        }
    }

    @Test fun assembledDefaultIdleTimerClosesUnusedAssociationWithoutReadiness() {
        val now = AtomicLong()
        Fixture(clock = now::get).use { f -> f.link().use { link ->
            await { f.server.stats().udp!!.associations == 1 && f.server.stats().server.loops.sumOf { it.timers } == 1 }
            now.set(UdpIdleTimeout.DNS_IDLE_NANOS)
            assertEquals(-1, link.control.getInputStream().read())
            await { f.server.stats().udp!!.associations == 0 }
            assertEquals(0, f.server.stats().udp!!.scratchBytes)
            assertEquals(0, f.server.stats().server.loops.sumOf { it.timers })
        } }
    }

    @Test fun twentyRunsStopMixedTrafficAndPendingDnsWithoutReplacingHungWorkers() {
        val release = CountDownLatch(1)
        val started = CountDownLatch(4)
        val lookup: (String) -> Array<InetAddress> = {
            started.countDown()
            while (release.count > 0) try { release.await() } catch (_: InterruptedException) { }
            arrayOf(loopback)
        }
        val resolver = SocksResolver.forTest()
        val workers = CopyOnWriteArrayList<Thread>()
        val server = SocksNioTcpServer(SocksNioTcpProfile.TCP_64, resolver,
            threadFactory = { task, name -> Thread(task, name).also(workers::add) }, udpProfile = SocksNioUdpProfile.UDP_64)
        var maxStop = 0L
        endpoint().use { target -> tcpEndpoint().use { tcpTarget ->
            try {
                repeat(20) { run ->
                    val credentials = SocksCredentials.of("u", "p")
                    val port = server.start(request(run.toLong(), lookup).copy(credentials = credentials))
                    assertEquals(0L, server.stats().udp!!.traffic.sentBytes)
                    assertEquals(0, server.stats().udp!!.peakQueuedBytes)
                    assertEquals((run + 1).toLong(), server.stats().runResolver!!.captureGeneration)
                    assertEquals(run.toLong(), server.stats().runResolver!!.networkGeneration)
                    assertFalse(server.invalidateNetwork(run - 1L))
                    val links = ArrayList<Link>()
                    val tcp = client(port, 1, tcpTarget.localPort)
                    val peer = tcpTarget.accept().apply { soTimeout = 3000 }
                    val pendingTcp = client(port, 1, tcpTarget.localPort, SocksDestination.Domain("hung$run-0.test"))
                    try {
                        assertEquals(0, reply(tcp)[1].toInt())
                        exchangeTcp(tcp, peer, payload(run, 99))
                        val live = link(port).also(links::add)
                        roundTrip(live, target, payload(run, 123))
                        repeat(if (run == 0) 4 else 1) { index ->
                            link(port).also(links::add).send(target.localPort, payload(index, 200),
                                SocksDestination.Domain("hung$run-$index.test"))
                        }
                        if (run == 0) assertTrue(started.await(3, TimeUnit.SECONDS))
                        await { server.stats().runResolver!!.subscribers == if (run == 0) 5 else 2 }
                        assertEquals(4, resolver.stats().workers)
                        assertEquals(4, resolver.stats().activeLookups)
                        assertEquals(links.size - 1, server.stats().udp!!.queuedPackets)
                        // Leave a real upstream response and TCP data in flight at stop.
                        live.send(target.localPort, payload(run, 511))
                        val packet = receive(target)
                        target.send(DatagramPacket(packet.data, packet.length, packet.socketAddress))
                        tcp.getOutputStream().write(payload(run, 1024))
                        val before = System.nanoTime()
                        if (run % 2 == 0) assertTrue(server.invalidateNetwork(run.toLong())) else assertTrue(server.stop())
                        val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - before)
                        maxStop = maxOf(maxStop, elapsed)
                        assertTrue("run $run stop $elapsed ms", elapsed < 2000)
                        assertClean(server)
                        assertFalse(credentials.matches(byteArrayOf('u'.code.toByte()), byteArrayOf('p'.code.toByte())))
                        assertEquals(4, resolver.stats().workers)
                        assertEquals(4, resolver.stats().activeLookups)
                        assertEquals(0, resolver.stats().queuedQueries)
                        assertEquals(0, resolver.stats().subscribers)
                        assertEquals(-1, pendingTcp.getInputStream().read())
                    } finally { links.forEach { it.close() }; tcp.close(); peer.close(); pendingTcp.close() }
                }
                assertEquals(40, workers.size)
                assertTrue(workers.none { it.isAlive })
                release.countDown()
                await { resolver.stats().activeLookups == 0 }
                val port = server.start(request(20))
                assertFalse(server.invalidateNetwork(19))
                link(port).use { roundTrip(it, target, payload(21, 81), SocksDestination.Domain("fresh.test")) }
                assertEquals(4, resolver.stats().workers)
                println("P4 restart runs=20 ownersPerRun=2 hungDnsWorkers=4 maxStopMs=$maxStop")
            } finally { release.countDown(); assertTrue(server.stop()); assertClean(server); assertTrue(resolver.shutdownForTest()) }
        } }
    }

    @Test fun stoppingInsideReceiveKeepsScratchUntilOwnerReturns() = stopInsideIo(false)
    @Test fun stoppingInsideSendReleasesQueueOnlyOnOwner() = stopInsideIo(true)

    private fun stopInsideIo(sending: Boolean) {
        val inside = CountDownLatch(1)
        val release = CountDownLatch(1)
        val io = object : UdpDataPlane.ChannelIo {
            fun pause() { inside.countDown(); assertTrue(release.await(3, TimeUnit.SECONDS)) }
            override fun receive(channel: DatagramChannel, scratch: ByteBuffer): InetSocketAddress? {
                val source = super.receive(channel, scratch)
                if (!sending && source != null) {
                    val first = scratch.array()[0]
                    pause()
                    assertEquals(first, scratch.array()[0])
                }
                return source
            }
            override fun send(channel: DatagramChannel, bytes: ByteBuffer, target: InetSocketAddress): Int {
                if (sending) pause()
                return super.send(channel, bytes, target)
            }
        }
        Fixture(io = io).use { f -> endpoint().use { target -> f.link().use { link ->
            try {
                link.send(target.localPort, payload(4, 111))
                assertTrue(inside.await(3, TimeUnit.SECONDS))
                assertFalse(f.server.stop(0))
                val stopped = f.server.stats()
                assertFalse(stopped.udp!!.open)
                assertEquals(1, stopped.udp.scratchBuffers)
                assertEquals(if (sending) 1 else 0, stopped.udp.queuedPackets)
                release.countDown()
                assertTrue(f.server.stop())
                assertClean(f.server)
                assertEquals(-1, link.control.getInputStream().read())
            } finally { release.countDown() }
        } } }
    }

    @Test fun mixedAssemblyKeepsTlsReadyBarrierAndDirectTcpAlongsideUdp() {
        tcpEndpoint().use { gatewayListener -> tcpEndpoint().use { direct -> endpoint().use { udpTarget ->
            val gateway = TlsGatewayChannel(gatewayListener.localPort,
                "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU".toByteArray(), "capture-p4", 7,
                TlsRoutingPolicy.freeze(TlsCaptureSettings(enabled = true, candidatePorts = setOf(443))), {})
            val request = request(7).copy(tlsGateway = gateway,
                route = { if (it.port == 443) SocksNioTcpServer.Route.TLS_GATEWAY else SocksNioTcpServer.Route.DIRECT })
            Fixture(startRequest = request).use { f -> f.link().use { udp ->
                roundTrip(udp, udpTarget, payload(1, 37))
                f.client(1, direct.localPort).use { plain -> direct.accept().use { peer ->
                    peer.soTimeout = 3000
                    assertEquals(0, reply(plain)[1].toInt())
                    exchangeTcp(plain, peer, payload(8, 42))
                    f.client(1, 443).use { tls -> gatewayListener.accept().use { hop ->
                        hop.soTimeout = 3000
                        assertArrayEquals("LAT1".toByteArray(), read(hop, 4))
                        val length = ByteBuffer.wrap(read(hop, 4)).int
                        assertTrue(length in 1..TlsGatewayChannel.MAX_HEADER_BYTES)
                        read(hop, length)
                        tls.soTimeout = 100
                        assertThrows(SocketTimeoutException::class.java) { tls.getInputStream().read() }
                        tls.soTimeout = 3000
                        val body = """{"version":1,"success":true,"errorCode":null}""".toByteArray()
                        hop.getOutputStream().write("LAT1".toByteArray() +
                            ByteBuffer.allocate(body.size + 4).putInt(body.size).put(body).array())
                        assertEquals(0, reply(tls)[1].toInt())
                        exchangeTcp(tls, hop, payload(5, 391))
                        roundTrip(udp, udpTarget, payload(2, 87))
                        await { f.server.stats().gatewayRelays == 1L }
                        val stats = f.server.stats()
                        assertEquals(2, stats.server.admission!!.tcp.current)
                        assertEquals(1, stats.server.admission.udp.current)
                        assertEquals(2, stats.eventLoopThreadsAlive)
                        assertTrue(stats.supportsTlsGateway)
                    } }
                } }
            } }
        } } }
    }

    @Test fun startupFailureClosesUdpRuntimeScopeCredentialsAndNextRunIsFresh() {
        val resolver = SocksResolver.forTest()
        val fail = AtomicBoolean(true)
        val server = SocksNioTcpServer(SocksNioTcpProfile.TCP_64, resolver,
            listenerFactory = { if (fail.getAndSet(false)) throw IOException("fixture bind") else ServerSocketChannel.open() },
            udpProfile = SocksNioUdpProfile.UDP_64)
        val first = request()
        try {
            assertThrows(IOException::class.java) { server.start(first) }
            assertClean(server, expectedFailure = true)
            assertFalse(first.credentials.matches(byteArrayOf(117), byteArrayOf(112)))
            val port = server.start(request(2))
            endpoint().use { target -> link(port).use { roundTrip(it, target, payload(5, 98)) } }
            assertEquals(2L, server.stats().runResolver!!.captureGeneration)
        } finally { assertTrue(server.stop()); assertClean(server); assertTrue(resolver.shutdownForTest()) }
    }

    private inner class Fixture(
        profile: SocksNioUdpProfile = SocksNioUdpProfile.UDP_64,
        startRequest: SocksNioTcpServer.StartRequest = request(),
        clock: () -> Long = System::nanoTime,
        io: UdpDataPlane.ChannelIo = UdpDataPlane.ChannelIo.CHANNEL
    ) : AutoCloseable {
        val resolver = SocksResolver.forTest()
        val workers = CopyOnWriteArrayList<Thread>()
        val prepares = AtomicInteger()
        val server = SocksNioTcpServer(SocksNioTcpProfile.TCP_64, resolver,
            threadFactory = { task, name -> Thread(task, name).also(workers::add) },
            sessionNanoClock = clock, udpProfile = profile, udpIo = io)
        val port = server.start(startRequest.copy(prepareUdp = {
            assertNotNull(it.channel)
            assertFalse(it.isBound)
            assertFalse(it.isConnected)
            assertTrue(Thread.currentThread().name.startsWith("SocksNio-"))
            prepares.incrementAndGet()
            checkNotNull(startRequest.prepareUdp).invoke(it)
        }))
        fun client(command: Int, target: Int) = client(port, command, target)
        fun link() = link(port)
        override fun close() {
            assertTrue(server.stop())
            assertClean(server)
            assertTrue(resolver.shutdownForTest())
        }
    }

    private inner class Link(val control: Socket, val relay: InetSocketAddress) : AutoCloseable {
        val client = endpoint()
        fun send(port: Int, bytes: ByteArray, destination: SocksDestination = SocksDestination.Ip(loopback)) {
            val encoded = wire(port, bytes, destination)
            client.send(DatagramPacket(encoded, encoded.size, relay))
        }
        fun response(): ByteArray {
            val packet = receive(client)
            return checkNotNull(SocksProtocol.decodeUdpRequest(packet.data, length = packet.length)).payload
        }
        override fun close() { control.close(); client.close() }
    }

    private fun link(port: Int): Link {
        val control = client(port, 3, 0)
        try {
            val reply = reply(control)
            assertArrayEquals(byteArrayOf(5, 0, 0, 1), reply.copyOf(4))
            return Link(control, InetSocketAddress(InetAddress.getByAddress(reply.copyOfRange(4, 8)),
                ((reply[8].toInt() and 255) shl 8) or (reply[9].toInt() and 255)))
        } catch (error: Throwable) { control.close(); throw error }
    }
    private fun request(network: Long = 0, lookup: (String) -> Array<InetAddress> = { arrayOf(loopback) }) =
        SocksNioTcpServer.StartRequest(SocksCredentials.of("u", "p"), network, lookup, {},
            { SocksNioTcpServer.Route.DIRECT }, prepareUdp = {})
    private fun client(port: Int, command: Int, target: Int,
        destination: SocksDestination = SocksDestination.Ip(loopback)): Socket = Socket().also {
        it.soTimeout = 3000
        it.connect(InetSocketAddress(loopback, port))
        it.getOutputStream().write(auth + SocksProtocol.encodeRequest(SocksRequest(command, destination, target)))
        assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(it, 4))
    }
    private fun reply(socket: Socket): ByteArray {
        val header = read(socket, 4)
        return header + read(socket, if (header[3].toInt() == 1) 6 else 18)
    }
    private fun read(socket: Socket, size: Int) = ByteArray(size).also { DataInputStream(socket.getInputStream()).readFully(it) }
    private fun wire(port: Int, bytes: ByteArray, destination: SocksDestination = SocksDestination.Ip(loopback)) =
        SocksProtocol.encodeUdpRequest(SocksUdpRequest(destination, port, bytes))
    private fun endpoint() = DatagramSocket(0, loopback).apply { soTimeout = 3000; receiveBufferSize = 1024 * 1024 }
    private fun tcpEndpoint() = ServerSocket(0, 64, loopback).apply { soTimeout = 3000 }
    private fun receive(socket: DatagramSocket) = DatagramPacket(ByteArray(65535), 65535).also(socket::receive)
    private fun DatagramPacket.payload() = data.copyOfRange(offset, offset + length)
    private fun payload(seed: Int, length: Int) = ByteArray(length) { ((it * 31) xor seed).toByte() }
    private fun roundTrip(link: Link, target: DatagramSocket, payload: ByteArray,
        destination: SocksDestination = SocksDestination.Ip(loopback)) {
        link.send(target.localPort, payload, destination)
        val packet = receive(target)
        assertArrayEquals(payload, packet.payload())
        target.send(DatagramPacket(packet.data, packet.length, packet.socketAddress))
        assertArrayEquals(payload, link.response())
    }
    private fun exchangeTcp(client: Socket, peer: Socket, bytes: ByteArray) {
        client.getOutputStream().write(bytes)
        assertArrayEquals(bytes, read(peer, bytes.size))
        val response = bytes.reversedArray()
        peer.getOutputStream().write(response)
        assertArrayEquals(response, read(client, response.size))
    }
    private fun noPacket(socket: DatagramSocket) {
        val timeout = socket.soTimeout
        try { socket.soTimeout = 100; assertThrows(SocketTimeoutException::class.java) { receive(socket) } }
        finally { socket.soTimeout = timeout }
    }
    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!condition()) { assertTrue("condition deadline", System.nanoTime() < deadline); Thread.sleep(2) }
    }
    private fun assertClean(server: SocksNioTcpServer, expectedFailure: Boolean = false) {
        await { server.stats().eventLoopThreadsAlive == 0 }
        val stats = server.stats()
        assertEquals(SocksNioServer.State.STOPPED, stats.server.state)
        if (expectedFailure) assertTrue(stats.server.failure is IOException) else assertNull(stats.server.failure)
        assertFalse(stats.runResolver!!.open)
        assertEquals(0, stats.runResolver.subscribers)
        assertEquals(0, stats.buffers!!.reservedBytes)
        assertEquals(0, stats.buffers.allocatedBytes)
        assertEquals(0, stats.server.admission!!.tcp.current)
        assertEquals(0, stats.server.admission.udp.current)
        assertEquals(0, stats.server.admission.handshakes.current)
        assertEquals(listOf(0, 0), stats.server.admission.ownerLoads)
        assertEquals(0, stats.server.admission.pendingReservations)
        assertFalse(stats.udp!!.open)
        assertEquals(0, stats.udp.associations)
        assertEquals(0, stats.udp.queuedPackets)
        assertEquals(0, stats.udp.queuedBytes)
        assertEquals(0, stats.udp.scratchBuffers)
        assertEquals(0, stats.udp.scratchBytes)
        stats.server.loops.forEach {
            assertEquals(0, it.channels); assertEquals(0, it.keys); assertEquals(0, it.resources)
            assertEquals(0, it.timers); assertEquals(0, it.commands); assertEquals(0, it.completions)
            assertEquals(0, it.readyKeys)
            assertEquals(0L, it.callbackFailures); assertEquals(0L, it.cleanupFailures)
        }
    }
}
