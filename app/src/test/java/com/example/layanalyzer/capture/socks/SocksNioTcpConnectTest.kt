// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.SocksSessionLimits
import java.io.IOException
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
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

class SocksNioTcpConnectTest {
    private val ipv4 = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val ipv6 = InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 })
    private val credentials = SocksCredentials.of("User", "Password")
    private val handshake = byteArrayOf(5, 1, 2, 1, 4) + "User".toByteArray() +
        byteArrayOf(8) + "Password".toByteArray()

    @Test fun ipv4ConnectProtectsAndBindsNativeAdapterBeforeNonblockingSyn() = upstream { target ->
        val events = ConcurrentLinkedQueue<String>()
        val io = object : SocksNioTcpConnect.ConnectIo {
            override fun connect(channel: SocketChannel, address: InetSocketAddress): Boolean {
                assertFalse(channel.isBlocking)
                assertFalse(channel.isConnected)
                assertTrue(channel.socket().isBound)
                events.add("connect")
                return channel.connect(address)
            }
        }
        fixture(io = io, prepare = { socket ->
            assertNotNull(socket.channel)
            assertTrue(socket.channel.isBlocking)
            assertFalse(socket.isConnected)
            events.add("protect")
            socket.bind(InetSocketAddress(ipv4, 0))
            events.add("bind")
        }).use { f ->
            f.client(target.localPort).use { client ->
                val reply = reply(client)
                assertEquals(0, reply[1].toInt())
                target.accept().use { remote ->
                    assertArrayEquals(SocksProtocol.encodeReply(0, remote.inetAddress, remote.port), reply)
                    val connected = f.connected()
                    f.owner(connected.client) {
                        assertEquals(SocksSession.State.TCP_CONNECTED, it.session.snapshot().state)
                        assertNull(it.session.snapshot().deadlineNanos)
                        assertEquals(0, connected.upstream.interestOps())
                        assertEquals(0, it.session.snapshot().bufferBytes)
                    }
                    assertEquals(listOf("protect", "bind", "connect"), events.toList())
                }
            }
        }
    }

    @Test fun ipv6SuccessUsesCompleteTwentyTwoByteBoundReply() = upstream(ipv6) { target ->
        fixture().use { f -> f.client(target.localPort, ipv6).use { client ->
            val bytes = reply(client)
            assertEquals(22, bytes.size)
            target.accept().use { remote ->
                assertArrayEquals(SocksProtocol.encodeReply(0, remote.inetAddress, remote.port), bytes)
            }
            f.connected()
        } }
    }

    @Test fun immediateConnectSuccessDoesNotWaitForConnectReadiness() = upstream { target ->
        val finishes = AtomicInteger()
        val io = object : SocksNioTcpConnect.ConnectIo {
            override fun connect(channel: SocketChannel, address: InetSocketAddress): Boolean {
                // Deterministically inject an immediate OS success, with a real bound endpoint
                // for the reply. Loopback connect + immediate finishConnect is not guaranteed to
                // finish in one call. Actual established sockets are covered by adjacent tests.
                channel.bind(InetSocketAddress(ipv4, 0))
                return true
            }
            override fun finishConnect(channel: SocketChannel): Boolean { finishes.incrementAndGet(); error("unexpected finish") }
        }
        fixture(io = io).use { f -> f.client(target.localPort).use { client ->
            assertEquals(0, reply(client)[1].toInt()); f.connected(); assertEquals(0, finishes.get())
        } }
    }

    @Test fun pendingConnectSendsNoSuccessOrPayloadUntilFinishConnect() = upstream { target ->
        val allow = AtomicBoolean()
        val finishes = AtomicInteger()
        fixture(io = pending(allow, finishes)).use { f -> f.client(target.localPort, payload = byteArrayOf(11, 12)).use { client ->
            val entry = f.entry()
            await { finishes.get() > 0 }
            assertNoData(client)
            target.accept().use { remote -> assertNoData(remote) }
            f.owner(entry) { assertEquals(SocksSession.State.CONNECTING, it.session.snapshot().state) }
            assertTrue(f.connections.isEmpty())
            allow.set(true)
            assertEquals(0, reply(client)[1].toInt()); f.connected()
        } }
    }

    @Test fun protectFailureNeverBindsOrConnectsAndReturnsGeneralFailure() = preparationFailure(false)
    @Test fun bindFailureNeverConnectsAndReturnsGeneralFailure() = preparationFailure(true)

    private fun preparationFailure(bind: Boolean) {
        val dials = AtomicInteger()
        val io = object : SocksNioTcpConnect.ConnectIo {
            override fun connect(channel: SocketChannel, address: InetSocketAddress): Boolean { dials.incrementAndGet(); return false }
        }
        fixture(io = io, prepare = { throw IOException(if (bind) "bind failed" else "protect failed") }).use { f ->
            f.client(80).use { client -> assertFailureAndEof(client) }
            assertEquals(0, dials.get())
            assertEquals(1, f.channels.size)
            assertTrue(f.channels.none { it.isOpen })
            f.assertReleased()
        }
    }

    @Test fun channelOpenFailureGetsBoundedReplyAndReleasesTcpLease() {
        fixture(io = object : SocksNioTcpConnect.ConnectIo { override fun open(): SocketChannel = throw IOException("open") }).use { f ->
            f.client(80).use(::assertFailureAndEof); f.assertReleased()
        }
    }

    @Test fun actualRefusedLoopbackConnectRepliesFailureAndPreservesCause() {
        val port = ServerSocket(0, 1, ipv4).use { it.localPort }
        fixture().use { f -> f.client(port).use { client ->
            val entry = f.entry()
            assertFailureAndEof(client)
            f.owner(entry) {
                assertEquals(SocksSession.State.CLOSED, it.session.snapshot().state)
                assertTrue(it.session.snapshot().closeCause is ConnectException)
                assertEquals(0, it.session.snapshot().bufferBytes)
            }
            f.assertReleased()
        } }
    }

    @Test fun synchronousConnectExceptionRepliesFailure() {
        fixture(io = object : SocksNioTcpConnect.ConnectIo {
            override fun connect(channel: SocketChannel, address: InetSocketAddress): Boolean = throw ConnectException("dial")
        }).use { f -> f.client(80).use(::assertFailureAndEof); f.assertReleased() }
    }

    @Test fun connectSecurityFailureRepliesWithoutTryingAnotherAddress() {
        val dials = AtomicInteger()
        fixture(io = object : SocksNioTcpConnect.ConnectIo {
            override fun connect(channel: SocketChannel, address: InetSocketAddress): Boolean {
                dials.incrementAndGet(); throw SecurityException("denied")
            }
        }, admitted = { entry, connector ->
            connector.connectResolved(entry, listOf(ipv4, ipv4), entry.session.ownerNowNanos() + TimeUnit.SECONDS.toNanos(15))
        }).use { f -> f.client(80).use(::assertFailureAndEof); assertEquals(1, dials.get()); f.assertReleased() }
    }

    @Test fun finishConnectExceptionRepliesFailure() = upstream { target ->
        fixture(io = object : SocksNioTcpConnect.ConnectIo {
            override fun finishConnect(channel: SocketChannel): Boolean = throw ConnectException("finish")
        }).use { f -> f.client(target.localPort).use(::assertFailureAndEof); f.assertReleased() }
    }

    @Test fun realTimerConnectTimeoutStillAllowsFailureReply() = upstream { target ->
        fixture(io = pending(), connectTimeout = TimeUnit.MILLISECONDS.toNanos(80)).use { f ->
            f.client(target.localPort).use(::assertFailureAndEof)
            assertTrue(f.connections.isEmpty()); f.assertReleased()
        }
    }

    @Test fun readinessAtExpiredDeadlineCannotProduceSuccess() = upstream { target ->
        val offset = AtomicLong()
        val allow = AtomicBoolean()
        val finishes = AtomicInteger()
        fixture(io = pending(allow, finishes), clock = { System.nanoTime() + offset.get() }).use { f ->
            f.client(target.localPort).use { client ->
                val entry = f.entry(); await { finishes.get() > 0 }
                f.owner(entry) { offset.addAndGet(SocksNioTcpConnect.CONNECT_TIMEOUT_NANOS); allow.set(true) }
                assertFailureAndEof(client)
                assertTrue(f.connections.isEmpty())
            }
        }
    }

    @Test fun timeSpentInPreparationCannotExtendDeadlineOrSendSyn() {
        val offset = AtomicLong()
        val dials = AtomicInteger()
        fixture(clock = { System.nanoTime() + offset.get() }, prepare = {
            offset.addAndGet(SocksNioTcpConnect.CONNECT_TIMEOUT_NANOS)
        }, io = object : SocksNioTcpConnect.ConnectIo {
            override fun connect(channel: SocketChannel, address: InetSocketAddress): Boolean { dials.incrementAndGet(); return false }
        }).use { f -> f.client(80).use(::assertFailureAndEof); assertEquals(0, dials.get()) }
    }

    @Test fun resolvedAttemptsShareDeadlineAndCloseFailedChannels() = upstream { target ->
        val dials = AtomicInteger()
        val deadlines = ConcurrentLinkedQueue<Long?>()
        val active = AtomicReference<SocksNioHandshake.AdmittedRequest>()
        fixture(io = object : SocksNioTcpConnect.ConnectIo {
            override fun connect(channel: SocketChannel, address: InetSocketAddress): Boolean {
                deadlines.add(active.get().session.snapshot().deadlineNanos)
                if (dials.incrementAndGet() == 1) throw ConnectException("first candidate")
                return channel.connect(address)
            }
        }, admitted = { entry, connector ->
            active.set(entry)
            connector.connectResolved(entry, listOf(ipv4, ipv4), entry.session.ownerNowNanos() + TimeUnit.SECONDS.toNanos(10))
        }).use { f -> f.client(target.localPort, destination = SocksDestination.Domain("never-resolve.invalid")).use { client ->
            assertEquals(0, reply(client)[1].toInt()); f.connected()
            assertEquals(2, dials.get()); assertEquals(1, deadlines.toSet().size)
            assertFalse(f.channels.first().isOpen)
        } }
    }

    @Test fun retryCannotRestartEstablishmentDeadline() {
        val offset = AtomicLong()
        val attempts = AtomicInteger()
        fixture(clock = { System.nanoTime() + offset.get() }, io = object : SocksNioTcpConnect.ConnectIo {
            override fun connect(channel: SocketChannel, address: InetSocketAddress): Boolean {
                attempts.incrementAndGet(); offset.addAndGet(TimeUnit.SECONDS.toNanos(16)); throw ConnectException("first")
            }
        }, admitted = { entry, connector ->
            connector.connectResolved(entry, listOf(ipv4, ipv4), entry.session.ownerNowNanos() + TimeUnit.SECONDS.toNanos(15))
        }).use { f -> f.client(80).use(::assertFailureAndEof); assertEquals(1, attempts.get()) }
    }

    @Test fun expiredResolutionDeadlineFailsBeforeChannelAllocation() {
        fixture(admitted = { entry, connector ->
            connector.connectResolved(entry, listOf(ipv4), entry.session.ownerNowNanos() - 1)
        }).use { f -> f.client(80).use(::assertFailureAndEof); assertTrue(f.channels.isEmpty()) }
    }

    @Test fun domainWithoutResolverFailsWithoutDnsOrChannelAllocation() {
        fixture().use { f -> f.client(80, destination = SocksDestination.Domain("never-resolve.invalid")).use(::assertFailureAndEof)
            assertTrue(f.channels.isEmpty()) }
    }

    @Test fun oversizedAddressResultFailsWithoutAllocatingChannel() {
        fixture(admitted = { entry, connector ->
            connector.connectResolved(entry, List(65) { ipv4 }, entry.session.ownerNowNanos() + TimeUnit.SECONDS.toNanos(15))
        }).use { f -> f.client(80).use(::assertFailureAndEof); assertTrue(f.channels.isEmpty()) }
    }

    @Test fun successReplyPartialWritesPrecedeDownstreamBytesAndKeepPayload() = upstream { target ->
        val payload = ByteArray(200) { it.toByte() }
        val received = AtomicReference<ByteArray>()
        fixture(clientIo = shortWrites(), connected = { connection ->
            val bytes = ByteBuffer.allocate(payload.size)
            assertEquals(payload.size, connection.client.readClient(bytes))
            received.set(bytes.array())
            assertEquals(1, connection.client.writeClient(ByteBuffer.wrap(byteArrayOf(42))))
        }).use { f -> f.client(target.localPort, payload = payload).use { client ->
            assertEquals(0, reply(client)[1].toInt()); assertEquals(42, client.getInputStream().read())
            f.connected(); assertArrayEquals(payload, received.get())
        } }
    }

    @Test fun zeroWriteSuccessDeadlineClosesBothChannelsWithoutHandoff() = upstream { target ->
        val calls = AtomicInteger()
        fixture(clientIo = zeroReplyWrites(calls), replyTimeout = TimeUnit.MILLISECONDS.toNanos(90)).use { f ->
            f.client(target.localPort).use { client -> assertEquals(-1, client.getInputStream().read()) }
            assertTrue(calls.get() in 1..300); assertTrue(f.connections.isEmpty()); f.assertReleased()
        }
    }

    @Test fun replyRecoversFromZeroAndPartialWritesWithoutDuplicatingBytes() = upstream { target ->
        val allow = AtomicBoolean()
        val blocked = CountDownLatch(1)
        val writingReply = AtomicBoolean()
        val io = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
            override fun write(channel: SocketChannel, source: ByteBuffer): Int {
                if (source.remaining() > 2) writingReply.set(true)
                if (writingReply.get() && !allow.get()) { blocked.countDown(); return 0 }
                val limit = source.limit()
                source.limit(source.position() + minOf(1, source.remaining()))
                return try { channel.write(source) } finally { source.limit(limit) }
            }
        }
        fixture(clientIo = io).use { f -> f.client(target.localPort).use { client ->
            assertTrue(blocked.await(3, TimeUnit.SECONDS)); assertNoData(client)
            assertTrue(f.connections.isEmpty())
            allow.set(true)
            val bytes = reply(client)
            target.accept().use { remote -> assertArrayEquals(SocksProtocol.encodeReply(0, remote.inetAddress, remote.port), bytes) }
            f.connected(); assertNoData(client)
        } }
    }

    @Test fun tcpLeaseRemainsHeldUntilBlockedFailureReplyDeadline() {
        val calls = AtomicInteger()
        fixture(prepare = { throw IOException("protect") }, clientIo = zeroReplyWrites(calls),
            replyTimeout = TimeUnit.MILLISECONDS.toNanos(350)).use { f ->
            f.client(80, payload = ByteArray(100)).use { client ->
                val entry = f.entry(); await { calls.get() > 0 }
                f.owner(entry) {
                    assertEquals(SocksSession.State.FAILING, it.session.snapshot().state)
                    assertTrue(it.session.snapshot().hasProtocolLease)
                    assertFalse(it.session.snapshot().hasHandshakeLease)
                    assertTrue(it.session.snapshot().bufferBytes <= 1024 + 22)
                }
                assertEquals(-1, client.getInputStream().read())
                f.owner(entry) {
                    assertEquals(0, it.session.snapshot().bufferBytes)
                    assertFalse(it.session.snapshot().hasProtocolLease)
                }
                f.assertReleased()
            }
        }
    }

    @Test fun zeroWriteFailureDeadlineClosesAndReleasesLease() {
        val calls = AtomicInteger()
        fixture(prepare = { throw IOException("protect") }, clientIo = zeroReplyWrites(calls),
            replyTimeout = TimeUnit.MILLISECONDS.toNanos(90)).use { f ->
            f.client(80).use { assertEquals(-1, it.getInputStream().read()) }
            assertTrue(calls.get() in 1..300); f.assertReleased()
        }
    }

    @Test fun partialFailureReplyIsCompleteBeforeEof() {
        fixture(prepare = { throw IOException("protect") }, clientIo = shortWrites()).use { f ->
            f.client(80).use(::assertFailureAndEof); f.assertReleased()
        }
    }

    @Test fun replyWriteExceptionClosesConnectedUpstream() = upstream { target ->
        fixture(clientIo = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
            override fun write(channel: SocketChannel, source: ByteBuffer): Int {
                if (source.remaining() > 2) throw IOException("write")
                return channel.write(source)
            }
        }).use { f -> f.client(target.localPort).use { assertEquals(-1, it.getInputStream().read()) }; f.assertReleased() }
    }

    @Test fun registrationCapacityFailureClosesUntransferredAndSessionChannels() {
        fixture(config = SocksEventLoopConfig(channelCapacity = 2, readinessPerTurn = 2)).use { f ->
            f.client(80).use { assertEquals(-1, it.getInputStream().read()) }; f.assertReleased()
            assertTrue(f.channels.none { it.isOpen })
        }
    }

    @Test fun retryTimerRejectionClosesSessionInsteadOfLeavingWritableSpin() = upstream { target ->
        fixture(io = pending(), config = SocksEventLoopConfig(timerCapacity = 1, timersPerTurn = 1)).use { f ->
            f.client(target.localPort).use { assertEquals(-1, it.getInputStream().read()) }; f.assertReleased()
        }
    }

    @Test fun downstreamCallbackExceptionClosesBothChannelsAndLease() = upstream { target ->
        fixture(connected = { throw IllegalStateException("downstream") }).use { f ->
            f.client(target.localPort).use { assertEquals(0, reply(it)[1].toInt()); assertEquals(-1, it.getInputStream().read()) }
            f.assertReleased()
        }
    }

    @Test fun connectingTcpSlotIsHeldAndRecoverableAfterFailure() = upstream { target ->
        fixture(io = pending(), connectTimeout = TimeUnit.MILLISECONDS.toNanos(350),
            limits = SocksSessionLimits(tcp = 1)).use { f ->
            f.client(target.localPort).use { first ->
                f.entry(); await { f.server.stats().admission!!.tcp.current == 1 }
                f.client(target.localPort).use(::assertFailureAndEof)
                assertEquals(1L, f.server.stats().admission!!.rejectedTcp)
                assertFailureAndEof(first); f.assertReleased()
                f.client(target.localPort).use { third -> f.entry(); assertFailureAndEof(third) }
            }
        }
    }

    @Test fun stopDuringPreparePreventsSynAndClosesUnownedChannel() {
        val fRef = AtomicReference<Fixture>()
        val dials = AtomicInteger()
        fixture(prepare = { assertFalse(fRef.get().server.stop()) }, io = object : SocksNioTcpConnect.ConnectIo {
            override fun connect(channel: SocketChannel, address: InetSocketAddress): Boolean { dials.incrementAndGet(); return false }
        }).use { f ->
            fRef.set(f)
            f.client(80).use { assertEquals(-1, it.getInputStream().read()) }
            assertEquals(0, dials.get())
        }
    }

    @Test fun stopWhileConnectingAndWhileReplyingCleansAllResources() = upstream { target ->
        repeat(8) { index ->
            fixture(io = if (index % 2 == 0) pending() else SocksNioTcpConnect.ConnectIo.CHANNEL,
                clientIo = if (index % 2 == 0) SocksNioHandshake.ClientIo.CHANNEL else zeroReplyWrites(AtomicInteger())).use { f ->
                f.client(target.localPort, payload = ByteArray(150)).use { client ->
                    val entry = f.entry()
                    await { f.channels.isNotEmpty() }
                    assertTrue(f.server.stop())
                    assertEquals(-1, client.getInputStream().read())
                    assertTrue(entry.session.resource.isClosed)
                }
            }
        }
    }

    @Test fun connectedIdleKeysDoNotSpinOrReadEarlyUpstreamData() = upstream { target ->
        fixture().use { f -> f.client(target.localPort).use { client ->
            assertEquals(0, reply(client)[1].toInt()); f.connected()
            target.accept().use { remote ->
                remote.getOutputStream().write(byteArrayOf(99))
                val callbacks = f.server.stats().loops.sumOf { it.readinessCallbacks }
                assertNoData(client)
                assertEquals(callbacks, f.server.stats().loops.sumOf { it.readinessCallbacks })
            }
        } }
    }

    private fun pending(allow: AtomicBoolean = AtomicBoolean(), calls: AtomicInteger = AtomicInteger()) =
        object : SocksNioTcpConnect.ConnectIo {
            override fun finishConnect(channel: SocketChannel): Boolean {
                calls.incrementAndGet()
                return allow.get() && channel.finishConnect()
            }
        }

    private fun shortWrites() = object : SocksNioHandshake.ClientIo {
        override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
        override fun write(channel: SocketChannel, source: ByteBuffer): Int {
            val limit = source.limit(); source.limit(source.position() + minOf(1, source.remaining()))
            return try { channel.write(source) } finally { source.limit(limit) }
        }
    }

    private fun zeroReplyWrites(calls: AtomicInteger) = object : SocksNioHandshake.ClientIo {
        override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
        override fun write(channel: SocketChannel, source: ByteBuffer): Int =
            if (source.remaining() > 2) { calls.incrementAndGet(); 0 } else channel.write(source)
    }

    private fun fixture(
        io: SocksNioTcpConnect.ConnectIo = SocksNioTcpConnect.ConnectIo.CHANNEL,
        prepare: (Socket) -> Unit = {},
        clientIo: SocksNioHandshake.ClientIo = SocksNioHandshake.ClientIo.CHANNEL,
        clock: () -> Long = System::nanoTime,
        connectTimeout: Long = SocksNioTcpConnect.CONNECT_TIMEOUT_NANOS,
        replyTimeout: Long = SocksNioTcpConnect.REPLY_TIMEOUT_NANOS,
        admitted: (SocksNioHandshake.AdmittedRequest, SocksNioTcpConnect) -> Unit = { entry, connector -> connector.connect(entry) },
        connected: (SocksNioTcpConnect.Connected) -> Unit = {},
        config: SocksEventLoopConfig = SocksEventLoopConfig(),
        limits: SocksSessionLimits = SocksSessionLimits()
    ) = Fixture(io, prepare, clientIo, clock, connectTimeout, replyTimeout, admitted, connected, config, limits)

    private inner class Fixture(
        io: SocksNioTcpConnect.ConnectIo, prepare: (Socket) -> Unit, clientIo: SocksNioHandshake.ClientIo,
        clock: () -> Long, connectTimeout: Long, replyTimeout: Long,
        admitted: (SocksNioHandshake.AdmittedRequest, SocksNioTcpConnect) -> Unit,
        connected: (SocksNioTcpConnect.Connected) -> Unit, config: SocksEventLoopConfig, limits: SocksSessionLimits
    ) : AutoCloseable {
        val channels = ConcurrentLinkedQueue<SocketChannel>()
        val entries = ConcurrentLinkedQueue<SocksNioHandshake.AdmittedRequest>()
        val connections = ConcurrentLinkedQueue<SocksNioTcpConnect.Connected>()
        val connector = SocksNioTcpConnect(prepare, { connection -> connected(connection); connections.add(connection) },
            connectTimeout, replyTimeout, object : SocksNioTcpConnect.ConnectIo {
                override fun open() = io.open().also { channels.add(it) }
                override fun connect(channel: SocketChannel, address: InetSocketAddress) = io.connect(channel, address)
                override fun finishConnect(channel: SocketChannel) = io.finishConnect(channel)
            })
        val server = SocksNioServer(SocksNioHandshake({ credentials }, { entry ->
            entries.add(entry); admitted(entry, connector)
        }, clientIo), config = config, sessionLimits = limits, sessionNanoClock = clock).also { it.start() }

        fun client(port: Int, address: InetAddress = ipv4, payload: ByteArray = byteArrayOf(),
            destination: SocksDestination = SocksDestination.Ip(address)): Socket = Socket().also {
            it.soTimeout = 3000
            it.connect(InetSocketAddress(ipv4, server.stats().port!!))
            it.getOutputStream().write(handshake + SocksProtocol.encodeRequest(SocksRequest(1, destination, port)) + payload)
            assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(it, 4))
        }

        fun entry(): SocksNioHandshake.AdmittedRequest { await { entries.isNotEmpty() }; return checkNotNull(entries.poll()) }
        fun connected(): SocksNioTcpConnect.Connected { await { connections.isNotEmpty() }; return checkNotNull(connections.poll()) }
        fun owner(entry: SocksNioHandshake.AdmittedRequest, action: (SocksNioHandshake.AdmittedRequest) -> Unit) {
            val done = CountDownLatch(1); val error = AtomicReference<Throwable>()
            assertEquals(SocksEventLoop.Submission.ACCEPTED, entry.session.owner.submit {
                try { action(entry) } catch (caught: Throwable) { error.set(caught) } finally { done.countDown() }
            })
            assertTrue(done.await(3, TimeUnit.SECONDS)); error.get()?.let { throw it }
        }
        fun assertReleased() {
            await { server.stats().admission!!.tcp.current == 0 }
            assertEquals(0, server.stats().admission!!.handshakes.current)
            assertTrue(channels.none { it.isOpen })
        }
        override fun close() {
            assertTrue(server.stop())
            val stats = server.stats()
            assertEquals(SocksNioServer.State.STOPPED, stats.state)
            assertEquals(0, stats.admission!!.handshakes.current)
            assertEquals(0, stats.admission.tcp.current); assertEquals(0, stats.admission.udp.current)
            assertEquals(listOf(0, 0), stats.admission.ownerLoads)
            stats.loops.forEach {
                assertEquals(0, it.channels); assertEquals(0, it.keys); assertEquals(0, it.resources)
                assertEquals(0, it.timers); assertEquals(0L, it.cleanupFailures)
            }
            assertTrue(channels.none { it.isOpen })
        }
    }

    private fun upstream(address: InetAddress = ipv4, action: (ServerSocket) -> Unit) {
        ServerSocket(0, 32, address).use { it.soTimeout = 3000; action(it) }
    }
    private fun reply(socket: Socket): ByteArray {
        val header = read(socket, 4)
        assertEquals(5, header[0].toInt()); assertEquals(0, header[2].toInt())
        return header + read(socket, when (header[3].toInt()) { 1 -> 6; 4 -> 18; else -> error("reply address") })
    }
    private fun assertFailureAndEof(socket: Socket) {
        assertArrayEquals(SocksProtocol.encodeReply(SocksProtocol.REPLY_GENERAL_FAILURE), reply(socket))
        assertEquals(-1, socket.getInputStream().read())
    }
    private fun read(socket: Socket, size: Int): ByteArray {
        val bytes = ByteArray(size); var offset = 0
        while (offset < size) {
            val count = socket.getInputStream().read(bytes, offset, size - offset)
            assertTrue("early EOF at $offset/$size", count > 0); offset += count
        }
        return bytes
    }
    private fun assertNoData(socket: Socket) {
        val old = socket.soTimeout; socket.soTimeout = 100
        try { assertThrows(SocketTimeoutException::class.java) { socket.getInputStream().read() } } finally { socket.soTimeout = old }
    }
    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (!condition()) { assertTrue("condition deadline", System.nanoTime() < deadline); Thread.sleep(2) }
    }
}
