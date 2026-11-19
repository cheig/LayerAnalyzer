// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.SocksSessionLimits
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class SocksNioTcpServerTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val auth = byteArrayOf(5, 1, 2, 1, 1, 'u'.code.toByte(), 1, 'p'.code.toByte())

    @Test fun ordinaryTcp64SimultaneousSessionsTransferAndRecoverAtCapacity() = capacity(SocksNioTcpProfile.TCP_64)
    @Test fun ordinaryTcp128SimultaneousSessionsTransferAndRecoverAtCapacity() = capacity(SocksNioTcpProfile.TCP_128)
    @Test fun ordinaryTcp256SimultaneousSessionsTransferAndRecoverAtCapacity() = capacity(SocksNioTcpProfile.TCP_256)

    private fun capacity(profile: SocksNioTcpProfile) {
        val resolver = SocksResolver.forTest()
        val workers = CopyOnWriteArrayList<Thread>()
        val clients = ArrayList<Socket>()
        EchoFixture().use { target ->
            val server = SocksNioTcpServer(profile, resolver, threadFactory = { task, name ->
                Thread(task, name).also { workers.add(it) }
            })
            try {
                val port = server.start(request())
                repeat(profile.tcp) { index ->
                    val payload = ByteArray(257) { (it * 31 + index).toByte() }
                    val client = client(port, target.port, payload = payload)
                    clients.add(client)
                    assertEquals(0, reply(client)[1].toInt())
                    assertArrayEquals(payload, read(client, payload.size))
                }
                await { target.active.get() == profile.tcp && server.stats().connectedRelays == profile.tcp.toLong() }
                val full = server.stats()
                assertEquals(profile.tcp, full.server.admission!!.tcp.current)
                assertEquals(profile.tcp, full.server.admission.tcp.peak)
                assertEquals(profile.tcp, full.server.admission.tcp.limit)
                assertEquals(profile.bufferBytes, full.buffers!!.reservedBytes)
                assertTrue(full.buffers.allocatedBytes <= profile.bufferBytes)
                assertEquals(2, workers.size)
                assertEquals(2, workers.count { it.isAlive })
                val threadIds = workers.map { it.id }
                assertEquals(0, full.processResolver.workers)
                assertEquals(0L, full.processResolver.lookups)
                assertEquals(1, target.fixtureThreads)
                // Every previously established connection remains live, not just the last one.
                clients.forEachIndexed { index, socket ->
                    val payload = ByteArray(513) { (index xor it).toByte() }
                    socket.getOutputStream().write(payload)
                    assertArrayEquals(payload, read(socket, payload.size))
                }
                client(port, target.port).use { overflow ->
                    assertEquals(1, reply(overflow)[1].toInt())
                    assertEquals(-1, overflow.getInputStream().read())
                }
                await { server.stats().server.admission!!.handshakes.current == 0 }
                assertEquals(1L, server.stats().server.admission!!.rejectedTcp)
                clients.removeAt(0).close()
                await { server.stats().server.admission!!.tcp.current == profile.tcp - 1 }
                client(port, target.port, payload = byteArrayOf(11, 22, 33)).use { replacement ->
                    assertEquals(0, reply(replacement)[1].toInt())
                    assertArrayEquals(byteArrayOf(11, 22, 33), read(replacement, 3))
                    assertEquals(profile.tcp, server.stats().server.admission!!.tcp.current)
                }
                assertEquals(threadIds, workers.map { it.id })
                assertEquals(2, server.stats().eventLoopThreadsAlive)
            } finally {
                clients.forEach { it.close() }
                assertTrue(server.stop())
                assertClean(server)
                assertTrue(resolver.shutdownForTest())
            }
        }
    }

    @Test fun profilesAreFiniteAndCannotRaiseBlockingOrUnmarkedInfrastructureLimits() {
        assertEquals(listOf(64, 128, 256, 512, 1024), SocksNioTcpProfile.entries.map { it.tcp })
        assertEquals(64, SocksSessionLimits().tcp)
        assertThrows(IllegalArgumentException::class.java) { SocksSessionLimits(tcp = 128) }
        assertThrows(IllegalArgumentException::class.java) { SocksEventLoopConfig(channelCapacity = 577) }
        SocksNioTcpProfile.entries.forEach { profile ->
            val config = profile.eventLoopConfig()
            assertEquals(profile, config.tcpValidationProfile)
            assertEquals(64 + 64 + 2 * profile.tcp + 1, config.channelCapacity)
            assertThrows(IllegalArgumentException::class.java) { config.copy(channelCapacity = config.channelCapacity + 1) }
            assertThrows(IllegalArgumentException::class.java) {
                SocksEventLoopGroup(config, sessionLimits = SocksSessionLimits(tcp = 32))
            }
        }
    }

    @Test fun tlsCandidatesAndUdpFailBeforeDnsSocketCreationAndReleaseAllLeases() {
        val resolver = SocksResolver.forTest()
        val prepares = AtomicInteger()
        val server = SocksNioTcpServer(SocksNioTcpProfile.TCP_64, resolver)
        try {
            val port = server.start(request(prepare = { prepares.incrementAndGet() },
                route = { SocksNioTcpServer.Route.TLS_GATEWAY }))
            client(port, 443, SocksDestination.Domain("tls.test")).use {
                assertEquals(1, reply(it)[1].toInt()); assertEquals(-1, it.getInputStream().read())
            }
            client(port, 53, command = SocksProtocol.COMMAND_UDP_ASSOCIATE).use {
                assertEquals(7, reply(it)[1].toInt()); assertEquals(-1, it.getInputStream().read())
            }
            await { server.stats().server.admission!!.ownerLoads == listOf(0, 0) }
            val stats = server.stats()
            assertEquals(1L, stats.rejectedRoutes); assertEquals(1L, stats.rejectedUdp)
            assertEquals(0, prepares.get()); assertEquals(0L, stats.processResolver.lookups)
            assertEquals(0, stats.buffers!!.reservedBytes)
            assertFalse(stats.supportsTlsGateway); assertFalse(stats.supportsUdp)
        } finally { assertTrue(server.stop()); assertClean(server); assertTrue(resolver.shutdownForTest()) }
    }

    @Test fun realSlowReceiverBoundsBuffersWhileAnotherFlowStillTransfers() {
        val resolver = SocksResolver.forTest()
        val server = SocksNioTcpServer(SocksNioTcpProfile.TCP_64, resolver)
        EchoFixture(initiallyPaused = true).use { slow -> EchoFixture().use { fast ->
            try {
                val port = server.start(request(prepare = { it.sendBufferSize = 2048 }))
                SocketChannel.open().use { channel ->
                    channel.socket().receiveBufferSize = 2048
                    channel.connect(InetSocketAddress(loopback, port))
                    val socket = channel.socket().apply { soTimeout = 4000 }
                    socket.getOutputStream().write(auth + requestBytes(slow.port))
                    assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(socket, 4))
                    assertEquals(0, reply(socket)[1].toInt())
                    channel.configureBlocking(false)
                    val block = ByteBuffer.wrap(ByteArray(64 * 1024) { it.toByte() })
                    var sent = 0L
                    var stalled = false
                    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(4)
                    while (!stalled && sent < 32L * 1024 * 1024 && System.nanoTime() < deadline) {
                        block.clear()
                        val count = channel.write(block)
                        sent += count
                        stalled = count == 0
                    }
                    assertTrue("real paused receiver must backpressure the sender", stalled)
                    await { server.stats().buffers!!.allocatedBytes >= SocksTcpBufferBudget.MAX_DIRECTION_BYTES }
                    client(port, fast.port, payload = byteArrayOf(1, 3, 5, 7)).use { other ->
                        assertEquals(0, reply(other)[1].toInt())
                        assertArrayEquals(byteArrayOf(1, 3, 5, 7), read(other, 4))
                    }
                    val buffers = server.stats().buffers!!
                    assertTrue(buffers.allocatedBytes <= 2 * 2 * SocksTcpBufferBudget.MAX_DIRECTION_BYTES)
                    assertTrue(buffers.peakAllocatedBytes <= server.profile.bufferBytes)
                    assertEquals(2, server.stats().eventLoopThreadsAlive)
                }
            } finally { assertTrue(server.stop()); assertClean(server); assertTrue(resolver.shutdownForTest()) }
        } }
    }

    @Test fun assembledHalfCloseDrainsPipelinedPayloadAndReturnsEchoBeforeEof() {
        val resolver = SocksResolver.forTest()
        val server = SocksNioTcpServer(SocksNioTcpProfile.TCP_64, resolver)
        EchoFixture().use { target ->
            try {
                val port = server.start(request())
                val payload = ByteArray(512 * 1024) { (it * 13).toByte() }
                client(port, target.port, payload = payload).use { socket ->
                    socket.shutdownOutput()
                    assertEquals(0, reply(socket)[1].toInt())
                    assertArrayEquals(payload, read(socket, payload.size))
                    assertEquals(-1, socket.getInputStream().read())
                }
                await { server.stats().server.admission!!.tcp.current == 0 }
                assertEquals(0, server.stats().buffers!!.allocatedBytes)
            } finally { assertTrue(server.stop()); assertClean(server); assertTrue(resolver.shutdownForTest()) }
        }
    }

    @Test fun twentyCompleteRunsFreezeRealGenerationsAndReuseFourHungDnsWorkers() {
        val resolver = SocksResolver.forTest()
        val release = CountDownLatch(1)
        val hungStarted = CountDownLatch(4)
        val server = SocksNioTcpServer(SocksNioTcpProfile.TCP_64, resolver)
        val lookup: (String) -> Array<InetAddress> = {
            hungStarted.countDown()
            while (release.count > 0) try { release.await() } catch (_: InterruptedException) { }
            arrayOf(loopback)
        }
        EchoFixture().use { target ->
            try {
                repeat(20) { index ->
                    val port = server.start(request(network = index.toLong(), lookup = lookup))
                    assertEquals((index + 1).toLong(), server.stats().server.captureGeneration)
                    assertEquals(server.stats().server.captureGeneration, server.stats().runResolver!!.captureGeneration)
                    assertEquals(index.toLong(), server.stats().runResolver!!.networkGeneration)
                    assertEquals(0L, server.stats().connectedRelays)
                    assertEquals(0, server.stats().buffers!!.peakAllocatedBytes)
                    client(port, target.port, payload = byteArrayOf(index.toByte())).use { transfer ->
                        assertEquals(0, reply(transfer)[1].toInt())
                        assertArrayEquals(byteArrayOf(index.toByte()), read(transfer, 1))
                        val dns = (0 until if (index == 0) 4 else 1).map { dnsIndex ->
                            client(port, target.port, SocksDestination.Domain("hung$index-$dnsIndex.test"))
                        }
                        try {
                            if (index == 0) assertTrue(hungStarted.await(3, TimeUnit.SECONDS))
                            await { server.stats().runResolver!!.subscribers == dns.size }
                            assertEquals(4, server.stats().processResolver.workers)
                            assertEquals(4, server.stats().processResolver.activeLookups)
                            val before = System.nanoTime()
                            if (index % 2 == 0) assertTrue(server.invalidateNetwork(index.toLong()))
                            else assertTrue(server.stop())
                            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - before) < 1000)
                            assertClean(server)
                            assertEquals(0, server.stats().processResolver.subscribers)
                            assertEquals(0, server.stats().processResolver.queuedQueries)
                            assertEquals(4, server.stats().processResolver.activeLookups)
                            assertEquals(-1, transfer.getInputStream().read())
                            dns.forEach { assertEquals(-1, it.getInputStream().read()) }
                        } finally { dns.forEach { it.close() } }
                    }
                }
                release.countDown()
                await { resolver.stats().activeLookups == 0 }
                val port = server.start(request(network = 20))
                assertFalse(server.invalidateNetwork(19))
                client(port, target.port, SocksDestination.Domain("fresh.test"), byteArrayOf(99)).use {
                    assertEquals(0, reply(it)[1].toInt()); assertArrayEquals(byteArrayOf(99), read(it, 1))
                }
                assertEquals(21L, server.stats().runResolver!!.captureGeneration)
                assertEquals(4, server.stats().processResolver.workers)
            } finally {
                release.countDown(); assertTrue(server.stop()); assertClean(server)
                assertTrue(resolver.shutdownForTest())
            }
        }
    }

    @Test fun normalDnsUsesRunNetworkLookupAndReservesBuffersBeforeLookup() {
        val resolver = SocksResolver.forTest()
        val server = SocksNioTcpServer(SocksNioTcpProfile.TCP_64, resolver)
        val seenReserved = AtomicInteger()
        val threadName = AtomicReference<String>()
        EchoFixture().use { target ->
            try {
                val port = server.start(request(network = 17, lookup = {
                    threadName.set(Thread.currentThread().name)
                    seenReserved.set(server.stats().buffers!!.reservedBytes)
                    arrayOf(loopback)
                }))
                client(port, target.port, SocksDestination.Domain("frozen.test"), byteArrayOf(8, 9)).use {
                    assertEquals(0, reply(it)[1].toInt()); assertArrayEquals(byteArrayOf(8, 9), read(it, 2))
                }
                assertEquals(2 * SocksTcpBufferBudget.MAX_DIRECTION_BYTES, seenReserved.get())
                assertTrue(threadName.get().startsWith("SocksDns-"))
                assertEquals(17L, server.stats().runResolver!!.networkGeneration)
            } finally { assertTrue(server.stop()); assertClean(server); assertTrue(resolver.shutdownForTest()) }
        }
    }

    @Test fun startupFailureClosesScopeAndAllowsNextGeneration() {
        val resolver = SocksResolver.forTest()
        val fail = AtomicBoolean(true)
        val server = SocksNioTcpServer(SocksNioTcpProfile.TCP_64, resolver,
            listenerFactory = { if (fail.getAndSet(false)) throw IOException("fixture bind failure") else ServerSocketChannel.open() })
        try {
            assertThrows(IOException::class.java) { server.start(request()) }
            assertClean(server)
            server.start(request())
            assertEquals(2L, server.stats().server.captureGeneration)
            assertEquals(2L, server.stats().runResolver!!.captureGeneration)
        } finally { assertTrue(server.stop()); assertClean(server); assertTrue(resolver.shutdownForTest()) }
    }

    @Test fun loopFailureClosesWholeAssemblyAndDetachesPendingDns() {
        val resolver = SocksResolver.forTest()
        val release = CountDownLatch(1)
        val started = CountDownLatch(1)
        val workers = CopyOnWriteArrayList<Thread>()
        val server = SocksNioTcpServer(SocksNioTcpProfile.TCP_64, resolver,
            threadFactory = { task, name -> Thread(task, name).also { workers.add(it) } })
        try {
            val port = server.start(request(lookup = { started.countDown(); release.await(); arrayOf(loopback) }))
            client(port, 80, SocksDestination.Domain("pending.test")).use {
                assertTrue(started.await(3, TimeUnit.SECONDS))
                workers[1].interrupt()
                await { server.stats().server.state == SocksNioServer.State.STOPPED }
                assertClean(server)
                assertEquals(0, resolver.stats().subscribers)
                assertEquals(-1, it.getInputStream().read())
            }
        } finally { release.countDown(); assertTrue(server.stop()); assertClean(server); assertTrue(resolver.shutdownForTest()) }
    }

    @Test fun stoppingPendingConnectClosesChannelAndReleasesReservation() {
        val resolver = SocksResolver.forTest()
        val attempts = CountDownLatch(1)
        val channels = CopyOnWriteArrayList<SocketChannel>()
        val server = SocksNioTcpServer(SocksNioTcpProfile.TCP_64, resolver,
            connectIo = object : SocksNioTcpConnect.ConnectIo {
                override fun open() = SocketChannel.open().also { channels.add(it) }
                override fun connect(channel: SocketChannel, address: InetSocketAddress): Boolean {
                    attempts.countDown(); return false // deterministic pending OP_CONNECT, no blocking
                }
            })
        try {
            val port = server.start(request())
            client(port, 80).use {
                assertTrue(attempts.await(3, TimeUnit.SECONDS))
                assertTrue(server.stop()); assertClean(server)
                assertTrue(channels.none { channel -> channel.isOpen })
                assertEquals(-1, it.getInputStream().read())
            }
        } finally { assertTrue(server.stop()); assertTrue(resolver.shutdownForTest()) }
    }

    private fun request(network: Long = 0, lookup: (String) -> Array<InetAddress> = { arrayOf(loopback) },
        prepare: (Socket) -> Unit = {}, route: (SocksRequest) -> SocksNioTcpServer.Route = { SocksNioTcpServer.Route.DIRECT }
    ) = SocksNioTcpServer.StartRequest(SocksCredentials.of("u", "p"), network, lookup, prepare, route)

    private fun requestBytes(port: Int, destination: SocksDestination = SocksDestination.Ip(loopback), command: Int = 1) =
        SocksProtocol.encodeRequest(SocksRequest(command, destination, port))

    private fun client(port: Int, upstreamPort: Int, destination: SocksDestination = SocksDestination.Ip(loopback),
        payload: ByteArray = byteArrayOf(), command: Int = 1): Socket = Socket().also {
        it.soTimeout = 5000; it.connect(InetSocketAddress(loopback, port))
        it.getOutputStream().write(auth + requestBytes(upstreamPort, destination, command) + payload)
        assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(it, 4))
    }

    private fun reply(socket: Socket): ByteArray {
        val header = read(socket, 4)
        assertEquals(5, header[0].toInt())
        return header + read(socket, if (header[3].toInt() == 1) 6 else 18)
    }
    private fun read(socket: Socket, count: Int): ByteArray {
        val bytes = ByteArray(count); var offset = 0
        while (offset < count) { val n = socket.getInputStream().read(bytes, offset, count - offset); assertTrue("unexpected EOF", n > 0); offset += n }
        return bytes
    }
    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!condition()) { assertTrue("condition deadline", System.nanoTime() < deadline); Thread.sleep(2) }
    }
    private fun assertClean(server: SocksNioTcpServer) {
        await { server.stats().eventLoopThreadsAlive == 0 }
        val stats = server.stats()
        assertEquals(SocksNioServer.State.STOPPED, stats.server.state)
        assertFalse(stats.runResolver!!.open); assertEquals(0, stats.runResolver.subscribers)
        assertEquals(0, stats.buffers!!.reservedBytes); assertEquals(0, stats.buffers.allocatedBytes)
        assertEquals(0, stats.server.admission!!.tcp.current); assertEquals(0, stats.server.admission.udp.current)
        assertEquals(0, stats.server.admission.handshakes.current); assertEquals(listOf(0, 0), stats.server.admission.ownerLoads)
        assertEquals(0, stats.server.admission.pendingReservations)
        stats.server.loops.forEach {
            assertEquals(0, it.channels); assertEquals(0, it.keys); assertEquals(0, it.resources)
            assertEquals(0, it.timers); assertEquals(0, it.commands); assertEquals(0, it.completions)
            assertEquals(0L, it.cleanupFailures)
        }
    }

    /** One fixed NIO fixture thread, independent of connection count, with a 16KiB buffer/peer. */
    private inner class EchoFixture(private val initiallyPaused: Boolean = false) : AutoCloseable {
        private val selector = Selector.open()
        private val listener = ServerSocketChannel.open().apply {
            configureBlocking(false); bind(InetSocketAddress(loopback, 0)); register(selector, SelectionKey.OP_ACCEPT)
        }
        val port = (listener.localAddress as InetSocketAddress).port
        val active = AtomicInteger()
        val fixtureThreads = 1
        private val stopped = AtomicBoolean()
        private val error = AtomicReference<Throwable>()
        private val worker = Thread({ run() }, "NioEchoFixture").apply { start() }

        private fun run() {
            try {
                while (!stopped.get()) {
                    selector.select(100)
                    val iterator = selector.selectedKeys().iterator()
                    while (iterator.hasNext()) {
                        val key = iterator.next(); iterator.remove()
                        if (!key.isValid) continue
                        if (key.isAcceptable) {
                            repeat(32) {
                                val channel = listener.accept() ?: return@repeat
                                channel.configureBlocking(false)
                                if (initiallyPaused) channel.socket().receiveBufferSize = 2048
                                channel.register(selector, if (initiallyPaused) 0 else SelectionKey.OP_READ, ByteBuffer.allocate(16 * 1024))
                                active.incrementAndGet()
                            }
                        } else {
                            val channel = key.channel() as SocketChannel
                            val buffer = key.attachment() as ByteBuffer
                            try {
                                if (key.isWritable) {
                                    buffer.flip(); channel.write(buffer); buffer.compact()
                                }
                                if (key.isReadable && buffer.hasRemaining()) {
                                    if (channel.read(buffer) < 0) {
                                        // READ is enabled only with no pending echo, so EOF never
                                        // throws away an earlier read's response.
                                        channel.close(); active.decrementAndGet(); continue
                                    }
                                }
                                key.interestOps(if (buffer.position() > 0) SelectionKey.OP_WRITE else SelectionKey.OP_READ)
                            } catch (_: IOException) { channel.close(); active.decrementAndGet() }
                        }
                    }
                }
            } catch (caught: Throwable) { if (!stopped.get()) error.set(caught) }
            finally {
                selector.keys().toList().forEach { it.channel().close() }
                selector.close()
            }
        }
        override fun close() {
            stopped.set(true); selector.wakeup(); worker.join(3000)
            assertFalse(worker.isAlive); error.get()?.let { throw it }
        }
    }
}
