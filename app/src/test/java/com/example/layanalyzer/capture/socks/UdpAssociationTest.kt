package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.SocksSessionLimits
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class UdpAssociationTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val credentials = SocksCredentials.of("User", "Password")
    private val handshake = byteArrayOf(5, 1, 2, 1, 4) + "User".toByteArray() +
        byteArrayOf(8) + "Password".toByteArray()

    @Test fun protectsNativeAdapterAndRegistersAllThreeChannelsOnOneOwner() {
        val events = ConcurrentLinkedQueue<String>()
        fixture(prepare = { socket ->
            assertNotNull(socket.channel)
            assertTrue(socket.channel.isBlocking)
            assertFalse(socket.isBound)
            assertFalse(socket.isConnected)
            events.add("protect-bind-network")
        }, io = object : UdpAssociation.ChannelIo {
            override fun bind(channel: DatagramChannel, address: InetSocketAddress) {
                assertFalse(channel.isBlocking)
                if (address.address.isAnyLocalAddress) assertEquals(listOf("protect-bind-network"), events.toList())
                super.bind(channel, address)
            }
        }).use { f -> f.client().use { client ->
            val reply = reply(client)
            val active = f.active()
            f.owner {
                assertSame(active.session.resource, active.relay.resource)
                assertSame(active.session.resource, active.upstream.resource)
                assertTrue(active.session.owner.inEventLoop())
                assertEquals(SocksSession.State.UDP_ACTIVE, active.session.snapshot().state)
                assertNull(active.session.snapshot().deadlineNanos)
                assertEquals(UdpAssociation.CONTROL_READ_BYTES, active.session.snapshot().bufferBytes)
                assertEquals(0, active.relay.interestOps())
                assertEquals(0, active.upstream.interestOps())
                val relay = active.relay.channel as DatagramChannel
                val bound = relay.localAddress as InetSocketAddress
                assertArrayEquals(SocksProtocol.encodeReply(0, loopback, bound.port), reply)
                assertTrue(bound.address.isLoopbackAddress)
                assertFalse(relay.isBlocking)
                assertFalse((active.upstream.channel as DatagramChannel).isBlocking)
                assertEquals(3 + if (active.session.owner === f.server.loop(0)) 1 else 0,
                    active.session.owner.stats().channels)
            }
            assertEquals(1, f.server.stats().admission!!.udp.current)
            assertEquals(0, f.server.stats().admission!!.tcp.current)
            assertEquals(0, f.server.stats().admission!!.handshakes.current)
        } }
    }

    @Test fun successorReceivesRealDatagramReadinessOnBothOriginalChannels() {
        val relayPacket = CountDownLatch(1)
        val upstreamPacket = CountDownLatch(1)
        fixture(active = { active ->
            listOf(active.relay to relayPacket, active.upstream to upstreamPacket).forEach { (registration, received) ->
                registration.replaceHandler { _, ops ->
                    assertTrue(active.session.owner.inEventLoop())
                    assertTrue(ops and SelectionKey.OP_READ != 0)
                    val bytes = ByteBuffer.allocate(32)
                    assertNotNull((registration.channel as DatagramChannel).receive(bytes))
                    assertArrayEquals(byteArrayOf(9, 8, 7), bytes.array().copyOf(bytes.position()))
                    received.countDown()
                }
                registration.interestOps(SelectionKey.OP_READ)
            }
        }).use { f -> f.client().use { client ->
            reply(client)
            val active = f.active()
            val ports = ArrayList<Int>()
            f.owner {
                listOf(active.relay, active.upstream).forEach { registration ->
                    ports.add(((registration.channel as DatagramChannel).localAddress as InetSocketAddress).port)
                }
            }
            DatagramSocket(0, loopback).use { sender ->
                ports.forEach { port -> sender.send(DatagramPacket(byteArrayOf(9, 8, 7), 3, loopback, port)) }
            }
            assertTrue(relayPacket.await(3, TimeUnit.SECONDS))
            assertTrue(upstreamPacket.await(3, TimeUnit.SECONDS))
        } }
    }

    @Test fun liveRelayEndpointCannotBeReusedByAnotherAssociation() = exclusiveEndpoint(false)

    @Test fun liveUpstreamEndpointCannotBeReusedByAnotherAssociation() = exclusiveEndpoint(true)

    private fun exclusiveEndpoint(upstream: Boolean) {
        var occupied: InetSocketAddress? = null
        fixture(io = object : UdpAssociation.ChannelIo {
            override fun bind(channel: DatagramChannel, address: InetSocketAddress) {
                if (address.address.isAnyLocalAddress != upstream) {
                    super.bind(channel, address)
                    return
                }
                // Force the ephemeral allocator's collision deterministically. Two
                // live associations must never share a receive endpoint, even when
                // they send to the same origin and use different client flow IDs.
                super.bind(channel, occupied ?: address)
                occupied = channel.localAddress as InetSocketAddress
            }
        }).use { f ->
            f.client().use { first ->
                assertEquals(0, reply(first)[1].toInt())
                val active = f.active()
                f.client().use(::assertFailure)
                await { f.server.stats().admission!!.udp.current == 1 }
                f.owner {
                    assertTrue(active.relay.channel.isOpen)
                    assertTrue(active.upstream.channel.isOpen)
                }
            }
            f.assertReleased()
        }
    }

    @Test fun controlEofClosesBothDatagramsAndReleasesExactlyOneLease() {
        val cleaned = AtomicInteger()
        fixture(active = { active -> active.ownDataPlane(AutoCloseable {
            assertFalse(active.relay.channel.isOpen)
            assertFalse(active.upstream.channel.isOpen)
            cleaned.incrementAndGet()
        }) }).use { f ->
            f.client().use { client -> reply(client); f.active(); client.shutdownOutput(); assertEquals(-1, client.getInputStream().read()) }
            f.assertReleased()
            f.owner { f.entry().session.close(); f.entry().session.close() }
            assertEquals(1, cleaned.get())
        }
    }

    @Test fun pipelinedAndLaterControlBytesAreDiscardedBeforeEof() {
        fixture().use { f -> f.client(ByteArray(1600) { 19 }).use { client ->
            reply(client)
            f.active()
            client.getOutputStream().write(ByteArray(3000) { 23 })
            client.shutdownOutput()
            assertEquals(-1, client.getInputStream().read())
            f.assertReleased()
        } }
    }

    @Test fun protectionFailureClosesPreparedAndRelayChannelsWithoutSuccess() {
        fixture(prepare = { throw IOException("protect rejected") }).use { f ->
            f.client().use(::assertFailure)
            f.assertReleased()
            assertEquals(2, f.channels.size)
            assertTrue(f.actives.isEmpty())
        }
    }

    @Test fun firstChannelOpenFailureReturnsFailureAndReleasesAssociation() = openFailure(1)
    @Test fun secondChannelOpenFailureClosesRegisteredRelay() = openFailure(2)

    private fun openFailure(at: Int) {
        val opens = AtomicInteger()
        fixture(io = object : UdpAssociation.ChannelIo {
            override fun open(): DatagramChannel {
                if (opens.incrementAndGet() == at) throw IOException("open")
                return DatagramChannel.open()
            }
        }).use { f -> f.client().use(::assertFailure); f.assertReleased() }
    }

    @Test fun relayBindFailureClosesUnownedChannel() = bindFailure(1)
    @Test fun upstreamBindFailureClosesUnownedAndRegisteredChannels() = bindFailure(2)

    private fun bindFailure(at: Int) {
        val binds = AtomicInteger()
        fixture(io = object : UdpAssociation.ChannelIo {
            override fun bind(channel: DatagramChannel, address: InetSocketAddress) {
                if (binds.incrementAndGet() == at) throw IOException("bind")
                super.bind(channel, address)
            }
        }).use { f -> f.client().use(::assertFailure); f.assertReleased() }
    }

    @Test fun relayRegistrationFailureClosesWholeSession() = registrationFailure(2)
    @Test fun upstreamRegistrationFailureClosesWholeSession() = registrationFailure(3)

    private fun registrationFailure(capacity: Int) {
        fixture(config = SocksEventLoopConfig(channelCapacity = capacity, readinessPerTurn = capacity)).use { f ->
            f.client().use { assertEquals(-1, it.getInputStream().read()) }
            f.assertReleased()
            assertTrue(f.actives.isEmpty())
        }
    }

    @Test fun setupDeadlineIsCheckedAfterProtectionBeforeSuccess() {
        val clock = AtomicLong(1000)
        fixture(clock = clock::get, prepare = { clock.addAndGet(UdpAssociation.SETUP_TIMEOUT_NANOS) }).use { f ->
            f.client().use(::assertFailure)
            f.assertReleased()
            f.owner { assertTrue(f.entry().session.snapshot().closeCause is SocksSession.DeadlineExceededException) }
        }
    }

    @Test fun setupDeadlineAfterBindClosesTheUnregisteredUpstream() {
        val clock = AtomicLong(1000)
        fixture(clock = clock::get, io = object : UdpAssociation.ChannelIo {
            override fun bind(channel: DatagramChannel, address: InetSocketAddress) {
                super.bind(channel, address)
                if (address.address.isAnyLocalAddress) clock.addAndGet(UdpAssociation.SETUP_TIMEOUT_NANOS)
            }
        }).use { f -> f.client().use(::assertFailure); f.assertReleased() }
    }

    @Test fun zeroAndPartialReplyWaitsBeforeActivatingAndDoesNotSpin() {
        val allow = AtomicBoolean()
        val writes = AtomicInteger()
        val started = AtomicBoolean()
        fixture(clientIo = replyIo { channel, source ->
            if (started.compareAndSet(false, true)) writeLimited(channel, source, 3)
            else if (!allow.get()) { writes.incrementAndGet(); 0 }
            else writeLimited(channel, source, 1)
        }).use { f -> f.client().use { client ->
            val prefix = read(client, 3)
            await { writes.get() >= 5 }
            f.owner {
                assertEquals(SocksSession.State.SOCKS_REPLY, f.entry().session.snapshot().state)
                assertTrue(f.actives.isEmpty())
                f.channels.forEach { assertTrue(it.isOpen) }
            }
            assertTrue(writes.get() < 500)
            allow.set(true)
            val bytes = prefix + read(client, 7)
            assertEquals(0, bytes[1].toInt())
            f.active()
        } }
    }

    @Test fun permanentZeroSuccessReplyExpiresAndClosesBothChannels() = stalledReply(false)
    @Test fun permanentZeroFailureReplyExpiresAndReleasesLease() = stalledReply(true)

    private fun stalledReply(failing: Boolean) {
        val writes = AtomicInteger()
        fixture(prepare = { if (failing) throw IOException("protect") }, replyTimeout = 40_000_000,
            clientIo = replyIo { _, _ -> writes.incrementAndGet(); 0 }).use { f ->
            f.client().use { assertEquals(-1, it.getInputStream().read()) }
            assertTrue(writes.get() in 1..100)
            f.assertReleased()
        }
    }

    @Test fun controlEofDuringPendingReplyClosesImmediately() {
        val writes = AtomicInteger()
        fixture(clientIo = replyIo { _, _ -> writes.incrementAndGet(); 0 }).use { f -> f.client().use { client ->
            await { writes.get() > 0 }
            client.shutdownOutput()
            assertEquals(-1, client.getInputStream().read())
            f.assertReleased()
            assertTrue(f.actives.isEmpty())
        } }
    }

    @Test fun controlEofAfterPartialSuccessStillClosesBothDatagrams() {
        val first = AtomicBoolean(true)
        fixture(clientIo = replyIo { channel, source ->
            if (first.getAndSet(false)) writeLimited(channel, source, 3) else 0
        }).use { f -> f.client().use { client ->
            assertArrayEquals(byteArrayOf(5, 0, 0), read(client, 3))
            client.shutdownOutput()
            assertEquals(-1, client.getInputStream().read())
            f.assertReleased()
            assertTrue(f.actives.isEmpty())
        } }
    }

    @Test fun replyWriteFailureClosesWholeAssociation() {
        fixture(clientIo = replyIo { _, _ -> throw IOException("write") }).use { f ->
            f.client().use { assertEquals(-1, it.getInputStream().read()) }
            f.assertReleased()
        }
    }

    @Test fun retryTimerRejectionClosesWholeAssociation() {
        fixture(clientIo = replyIo { _, _ -> 0 },
            config = SocksEventLoopConfig(timerCapacity = 1, timersPerTurn = 1)).use { f ->
            f.client().use { assertEquals(-1, it.getInputStream().read()) }
            f.assertReleased()
            f.owner { assertTrue(f.entry().session.snapshot().closeCause is SocksSession.SchedulingRejectedException) }
        }
    }

    @Test fun stopDuringProtectionClosesCallerOwnedChannelAndExistingScope() {
        val server = AtomicReference<SocksNioServer>()
        fixture(prepare = { server.get().stop(0) }).use { f ->
            server.set(f.server)
            f.client().use { assertEquals(-1, it.getInputStream().read()) }
            await { f.server.stats().state == SocksNioServer.State.STOPPED }
            assertTrue(f.channels.none { it.isOpen })
            assertTrue(f.actives.isEmpty())
        }
    }

    @Test fun stopAfterReplyWriteCannotActivateSuccessor() {
        val server = AtomicReference<SocksNioServer>()
        fixture(clientIo = replyIo { channel, source -> channel.write(source).also { server.get().stop(0) } }).use { f ->
            server.set(f.server)
            f.client().use { reply(it); assertEquals(-1, it.getInputStream().read()) }
            await { f.server.stats().state == SocksNioServer.State.STOPPED }
            assertTrue(f.actives.isEmpty())
        }
    }

    @Test fun stopWhileReplyIsStalledCancelsItsRetryAndAllChannels() {
        val writes = AtomicInteger()
        fixture(clientIo = replyIo { _, _ -> writes.incrementAndGet(); 0 }).use { f ->
            f.client().use { client ->
                await { writes.get() > 0 }
                assertTrue(f.server.stop())
                assertEquals(-1, client.getInputStream().read())
            }
            assertTrue(f.actives.isEmpty())
        }
    }

    @Test fun successorExceptionStillReleasesChannelsBuffersAndLease() {
        fixture(active = { throw IOException("successor") }).use { f ->
            f.client().use { reply(it); assertEquals(-1, it.getInputStream().read()) }
            f.assertReleased()
        }
    }

    @Test fun throwingCleanupIsCountedAndCannotLeakAssociationLease() {
        fixture(active = { it.ownDataPlane(AutoCloseable { throw IOException("cleanup") }) }).use { f ->
            f.client().use { reply(it); f.active(); it.shutdownOutput(); assertEquals(-1, it.getInputStream().read()) }
            f.assertReleased()
            f.owner { assertEquals(1L, f.entry().session.snapshot().udpCleanupFailures) }
        }
    }

    @Test fun idleControlHasNoWriteInterestOrPerAssociationTimer() {
        fixture().use { f -> f.client().use { client ->
            reply(client)
            val active = f.active()
            f.owner { assertEquals(0, active.session.owner.stats().timers) }
            val callbacks = active.session.owner.stats().readinessCallbacks
            client.soTimeout = 50
            assertThrows(SocketTimeoutException::class.java) { client.getInputStream().read() }
            f.owner { assertEquals(callbacks, active.session.owner.stats().readinessCallbacks) }
        } }
    }

    private fun replyIo(write: (SocketChannel, ByteBuffer) -> Int) = object : SocksNioHandshake.ClientIo {
        var reply = false
        override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
        override fun write(channel: SocketChannel, source: ByteBuffer): Int {
            if (source.remaining() > 2) reply = true
            return if (reply) write(channel, source) else channel.write(source)
        }
    }

    private fun writeLimited(channel: SocketChannel, source: ByteBuffer, bytes: Int): Int {
        val limit = source.limit()
        source.limit(source.position() + minOf(source.remaining(), bytes))
        return try { channel.write(source) } finally { source.limit(limit) }
    }

    private fun fixture(
        prepare: (DatagramSocket) -> Unit = {},
        active: (UdpAssociation.Active) -> Unit = {},
        io: UdpAssociation.ChannelIo = UdpAssociation.ChannelIo.CHANNEL,
        clientIo: SocksNioHandshake.ClientIo = SocksNioHandshake.ClientIo.CHANNEL,
        config: SocksEventLoopConfig = SocksEventLoopConfig(),
        clock: () -> Long = System::nanoTime,
        replyTimeout: Long = UdpAssociation.REPLY_TIMEOUT_NANOS
    ) = Fixture(prepare, active, io, clientIo, config, clock, replyTimeout)

    private inner class Fixture(
        prepare: (DatagramSocket) -> Unit, active: (UdpAssociation.Active) -> Unit,
        io: UdpAssociation.ChannelIo, clientIo: SocksNioHandshake.ClientIo,
        config: SocksEventLoopConfig, clock: () -> Long, replyTimeout: Long
    ) : AutoCloseable {
        val channels = ConcurrentLinkedQueue<DatagramChannel>()
        val entries = ConcurrentLinkedQueue<SocksNioHandshake.AdmittedRequest>()
        val actives = ConcurrentLinkedQueue<UdpAssociation.Active>()
        val association = UdpAssociation(prepare, { active(it); actives.add(it) },
            replyTimeoutNanos = replyTimeout, io = object : UdpAssociation.ChannelIo {
                override fun open() = io.open().also { channels.add(it) }
                override fun bind(channel: DatagramChannel, address: InetSocketAddress) = io.bind(channel, address)
            })
        val server = SocksNioServer(SocksNioHandshake({ credentials }, {
            entries.add(it)
            association.start(it)
        }, clientIo), config = config, sessionLimits = SocksSessionLimits(), sessionNanoClock = clock).also { it.start() }

        fun client(payload: ByteArray = byteArrayOf()): Socket = Socket().also {
            it.soTimeout = 3000
            it.connect(InetSocketAddress(loopback, server.stats().port!!))
            it.getOutputStream().write(handshake + SocksProtocol.encodeRequest(
                SocksRequest(3, SocksDestination.Ip(loopback), 0)) + payload)
            assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(it, 4))
        }

        fun entry(): SocksNioHandshake.AdmittedRequest { await { entries.isNotEmpty() }; return checkNotNull(entries.peek()) }
        fun active(): UdpAssociation.Active { await { actives.isNotEmpty() }; return checkNotNull(actives.peek()) }
        fun owner(action: () -> Unit) {
            val done = CountDownLatch(1)
            val error = AtomicReference<Throwable>()
            assertEquals(SocksEventLoop.Submission.ACCEPTED, entry().session.owner.submit {
                try { action() } catch (caught: Throwable) { error.set(caught) } finally { done.countDown() }
            })
            assertTrue(done.await(3, TimeUnit.SECONDS))
            error.get()?.let { throw it }
        }

        fun assertReleased() {
            await { server.stats().admission!!.udp.current == 0 }
            assertEquals(0, server.stats().admission!!.handshakes.current)
            assertEquals(0, server.stats().admission!!.tcp.current)
            assertEquals(listOf(0, 0), server.stats().admission!!.ownerLoads)
            assertTrue(channels.none { it.isOpen })
            owner {
                val snapshot = entry().session.snapshot()
                assertEquals(SocksSession.State.CLOSED, snapshot.state)
                assertEquals(0, snapshot.bufferBytes)
                assertEquals(0, snapshot.buffers)
                assertNull(snapshot.deadlineNanos)
            }
        }

        override fun close() {
            assertTrue(server.stop())
            val stats = server.stats()
            assertEquals(SocksNioServer.State.STOPPED, stats.state)
            assertEquals(0, stats.admission!!.handshakes.current)
            assertEquals(0, stats.admission.tcp.current)
            assertEquals(0, stats.admission.udp.current)
            assertEquals(listOf(0, 0), stats.admission.ownerLoads)
            stats.loops.forEach {
                assertEquals(0, it.channels)
                assertEquals(0, it.keys)
                assertEquals(0, it.resources)
                assertEquals(0, it.timers)
                assertEquals(0, it.commands)
                assertEquals(0, it.completions)
                assertEquals(0L, it.cleanupFailures)
            }
            assertTrue(channels.none { it.isOpen })
        }
    }

    private fun reply(socket: Socket): ByteArray {
        val header = read(socket, 4)
        assertEquals(5, header[0].toInt())
        assertEquals(0, header[2].toInt())
        return header + read(socket, when (header[3].toInt()) { 1 -> 6; 4 -> 18; else -> error("address") })
    }

    private fun assertFailure(socket: Socket) {
        assertArrayEquals(SocksProtocol.encodeReply(1), reply(socket))
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

    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (!condition()) { assertTrue("condition deadline", System.nanoTime() < deadline); Thread.sleep(2) }
    }
}
