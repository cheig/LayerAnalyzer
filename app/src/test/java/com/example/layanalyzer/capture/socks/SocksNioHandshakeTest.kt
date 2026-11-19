// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.SocksSessionLimits
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class SocksNioHandshakeTest {
    private val credentials = SocksCredentials.of("User", "Password")
    private val greeting = byteArrayOf(5, 1, 2)
    private val auth = byteArrayOf(1, 4) + "User".toByteArray() + byteArrayOf(8) + "Password".toByteArray()
    private val ipv4 = SocksDestination.Ip(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
    private val destinations = listOf(ipv4,
        SocksDestination.Ip(InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 })),
        SocksDestination.Domain("Do-Not-Resolve.example.invalid"), SocksDestination.Domain("x".repeat(255)))
    private val request = SocksRequest(1, ipv4, 80)
    private val entries = ConcurrentLinkedQueue<SocksNioHandshake.AdmittedRequest>()

    @Test fun allAddressTypesAndCommandsUseActualSelectorAndExactRequests() = withServer { server ->
        for (destination in destinations) for (command in listOf(1, 3)) {
            val expected = SocksRequest(command, destination, 65535)
            connect(server).use { socket ->
                sendAll(socket, expected)
                assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(socket, 4))
                val entry = nextEntry()
                assertEquals(expected, entry.request)
                onOwner(entry) {
                    val snapshot = it.session.snapshot()
                    assertEquals(SocksSession.State.ADMITTED, snapshot.state)
                    assertFalse(snapshot.hasHandshakeLease)
                    assertTrue(snapshot.hasProtocolLease)
                    assertEquals(if (command == 1) SocksSessionAdmission.Protocol.TCP else SocksSessionAdmission.Protocol.UDP, snapshot.protocol)
                    assertEquals(0, snapshot.bufferBytes)
                    it.session.close()
                }
                eof(socket)
            }
        }
    }
    @Test fun everyByteFragmentAuthenticatesAndDeliversOnce() {
        val io = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer): Int {
                val limit = target.limit(); target.limit(target.position() + 1)
                return try { channel.read(target) } finally { target.limit(limit) }
            }
            override fun write(channel: SocketChannel, source: ByteBuffer) = channel.write(source)
        }
        withServer(io = io) { server ->
            connect(server).use { socket ->
                val wire = greeting + auth + SocksProtocol.encodeRequest(request)
                wire.forEach { socket.getOutputStream().write(it.toInt() and 255) }
                assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(socket, 4))
                assertEquals(request, nextEntry().request)
                assertNoData(socket)
                assertTrue(entries.isEmpty())
            }
        }
    }
    @Test fun everyTwoWaySplitAcrossGreetingAuthRequestAndHttpSuffixIsLossless() = withServer { server ->
        val payload = "GET / HTTP/1.1\r\nHost: fixture\r\n\r\n".toByteArray()
        val wire = greeting + auth + SocksProtocol.encodeRequest(request) + payload
        for (split in 0..wire.size) {
            connect(server).use { socket ->
                socket.getOutputStream().write(wire, 0, split)
                socket.getOutputStream().write(wire, split, wire.size - split)
                assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(socket, 4))
                val entry = nextEntry()
                assertArrayEquals(payload, collect(entry, payload.size, 3))
                onOwner(entry) { it.session.close() }
                eof(socket)
            }
        }
    }
    @Test fun coalescedClientHelloRemainsOwnedAndNoFakeSuccessOrApplicationWriteOccurs() = withServer { server ->
        val hello = byteArrayOf(0x16, 3, 1, 0, 8, 1, 0, 0, 4, 0xff.toByte(), 0, 42, 12)
        connect(server).use { socket ->
            sendAll(socket, request, hello)
            assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(socket, 4))
            assertArrayEquals(hello, collect(nextEntry(), hello.size, 1))
            assertNoData(socket)
        }
    }
    @Test fun full1024ByteReadAndMegabytePayloadSurviveTinyPrefixReadsAndSocketBackpressure() {
        val reads = ConcurrentLinkedQueue<Int>()
        val io = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer): Int = channel.read(target).also { reads.add(it) }
            override fun write(channel: SocketChannel, source: ByteBuffer) = channel.write(source)
        }
        withServer(io = io) { server ->
            val payload = ByteArray(1024 * 1024) { (it * 31).toByte() }
            connect(server).use { socket ->
                val writerError = AtomicReference<Throwable>()
                val writer = Thread { try { sendAll(socket, request, payload) } catch (error: Throwable) { writerError.set(error) } }
                writer.start()
                assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(socket, 4))
                val entry = nextEntry()
                onOwner(entry) {
                    assertTrue(it.bufferedClientBytes > 0)
                    assertEquals(SocksNioHandshake.INPUT_BYTES, it.session.snapshot().bufferBytes)
                    val before = it.bufferedClientBytes
                    assertEquals(0, it.readClient(ByteBuffer.allocate(0)))
                    assertEquals(before, it.bufferedClientBytes)
                }
                assertArrayEquals(payload, collect(entry, payload.size, 7))
                writer.join(3_000); assertFalse(writer.isAlive); assertNull(writerError.get())
                assertTrue("actual full control read", reads.contains(1024))
                onOwner(entry) { assertEquals(0, it.session.snapshot().bufferBytes); it.session.close() }
                eof(socket)
            }
        }
    }
    @Test fun laterSocketPayloadIsNeverReadBeforeDownstreamArmsOrPulls() = withServer { server ->
        connect(server).use { socket ->
            sendAll(socket)
            read(socket, 4)
            val entry = nextEntry()
            onOwner(entry) { assertEquals(0, it.bufferedClientBytes) }
            val payload = ByteArray(8192) { it.toByte() }
            socket.getOutputStream().write(payload)
            assertArrayEquals(payload, collect(entry, payload.size, 111))
        }
    }
    @Test fun successorReadinessHandlerReceivesActualChannelAfterSingleHandoff() = withServer { server ->
        connect(server).use { socket ->
            sendAll(socket); read(socket, 4)
            val entry = nextEntry()
            val result = AtomicInteger(-1)
            onOwner(entry) {
                it.onReady { admitted, ops ->
                    assertTrue(ops and SelectionKey.OP_READ != 0)
                    val target = ByteBuffer.allocate(1)
                    if (admitted.readClient(target) > 0) {
                        result.set(target.get(0).toInt()); admitted.interestOps(0)
                    }
                }
                it.interestOps(SelectionKey.OP_READ)
            }
            socket.getOutputStream().write(42)
            await { result.get() == 42 }
            assertTrue(entries.isEmpty())
        }
    }
    @Test fun noAcceptableMethodAndZeroMethodsHaveExactFailureWire() = withServer { server ->
        listOf(byteArrayOf(5, 0), byteArrayOf(5, 2, 0, 1)).forEach { wire ->
            connect(server).use { it.getOutputStream().write(wire); assertArrayEquals(byteArrayOf(5, 255.toByte()), read(it, 2)); eof(it) }
        }
        assertTrue(entries.isEmpty())
    }
    @Test fun wrongGreetingVersionClosesImmediatelyWithNoReply() = withServer { server ->
        connect(server).use { it.getOutputStream().write(4); eof(it) }
    }
    @Test fun wrongCredentialVersionAndEmptyLengthsHaveExactAuthFailure() = withServer { server ->
        listOf(auth.clone().also { it[0] = 5 }, auth.clone().also { it[2] = 65 }, byteArrayOf(1, 0, 0)).forEach { candidate ->
            connect(server).use { socket ->
                socket.getOutputStream().write(greeting + candidate)
                assertArrayEquals(byteArrayOf(5, 2, 1, 1), read(socket, 4)); eof(socket)
            }
        }
    }
    @Test fun missingCredentialsFailAuthentication() = withServer(credentialsProvider = { null }) { server ->
        connect(server).use { sendAll(it); assertArrayEquals(byteArrayOf(5, 2, 1, 1), read(it, 4)); eof(it) }
    }
    @Test fun max255ByteMethodsUsernamePasswordAndDomainAreAccepted() {
        val pair = SocksCredentials.of("u".repeat(255), "p".repeat(255))
        withServer(credentialsProvider = { pair }) { server ->
            connect(server).use { socket ->
                val methods = ByteArray(255).also { it[254] = 2 }
                val longAuth = byteArrayOf(1, 255.toByte()) + pair.username.toByteArray() + byteArrayOf(255.toByte()) + pair.password.toByteArray()
                val expected = SocksRequest(1, destinations.last(), 443)
                socket.getOutputStream().write(byteArrayOf(5, 255.toByte()) + methods + longAuth + SocksProtocol.encodeRequest(expected))
                assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(socket, 4))
                assertEquals(expected, nextEntry().request)
            }
        }
    }
    @Test fun malformedRequestVersionAddressTypeAndZeroDomainCloseSilentlyAfterAuth() = withServer { server ->
        listOf(byteArrayOf(4), byteArrayOf(5, 1, 0, 2), byteArrayOf(5, 1, 0, 3, 0)).forEach { wire ->
            connect(server).use { socket ->
                socket.getOutputStream().write(greeting + auth + wire)
                assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(socket, 4)); eof(socket)
            }
        }
    }
    @Test fun unsupportedCommandReturnsExactBoundLoopbackFailure() = withServer { server ->
        connect(server).use { socket ->
            sendAll(socket, request.copy(command = 2))
            assertArrayEquals(byteArrayOf(5, 2, 1, 0) + SocksProtocol.encodeReply(7), read(socket, 14)); eof(socket)
        }
        await { server.stats().admission!!.handshakes.current == 0 }
        assertEquals(0, server.stats().admission!!.tcp.peak)
    }
    @Test fun eofAtEveryGreetingAuthAndRequestPrefixClosesAndReleasesStorage() = withServer { server ->
        val wire = greeting + auth + SocksProtocol.encodeRequest(request)
        for (size in 0 until wire.size) {
            connect(server).use { socket ->
                socket.getOutputStream().write(wire, 0, size); socket.shutdownOutput()
                val expectedReplies = (if (size >= greeting.size) 2 else 0) + (if (size >= greeting.size + auth.size) 2 else 0)
                if (expectedReplies > 0) read(socket, expectedReplies)
                eof(socket)
            }
            await { server.stats().admission!!.handshakes.current == 0 }
        }
        assertTrue(entries.isEmpty())
    }
    @Test fun fixedDeadlineDoesNotRefreshForFragmentsOrAuthToRequestTransition() {
        val shift = AtomicLong()
        withServer(clock = { System.nanoTime() + shift.get() }) { server ->
            connect(server).use { socket ->
                socket.getOutputStream().write(greeting + auth)
                assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(socket, 4))
                shift.set(TimeUnit.SECONDS.toNanos(14))
                val before = server.stats().loops.sumOf { it.readinessCallbacks }
                socket.getOutputStream().write(byteArrayOf(5, 1))
                await { server.stats().loops.sumOf { it.readinessCallbacks } > before }
                shift.set(TimeUnit.SECONDS.toNanos(16))
                socket.getOutputStream().write(byteArrayOf(0, 1, 127, 0, 0, 1, 0, 80))
                eof(socket)
            }
            assertTrue(entries.isEmpty())
        }
    }
    @Test fun silentPeerTimesOutWithShortInjectedAdmissionDeadline() = withServer(timeoutNanos = TimeUnit.MILLISECONDS.toNanos(80)) { server ->
        connect(server).use { eof(it) }
        await { server.stats().admission!!.handshakes.current == 0 }
    }
    @Test fun queuedPartialControlWriteSharesHandshakeDeadlineAndDoesNotSpin() {
        val writes = AtomicInteger()
        val io = zeroWrites(writes)
        withServer(io = io, timeoutNanos = TimeUnit.MILLISECONDS.toNanos(80)) { server ->
            connect(server).use { socket -> socket.getOutputStream().write(greeting); eof(socket) }
            assertTrue(writes.get() > 0)
            assertTrue("empty select backoff bounds synthetic writable zero", writes.get() < 2000)
        }
    }
    @Test fun singleByteAndZeroWritesDrainRepliesBeforeAdmissionAndArmOnlyPendingOutput() {
        val calls = AtomicInteger()
        val acceptedAt = AtomicInteger(-1)
        val io = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
            override fun write(channel: SocketChannel, source: ByteBuffer): Int {
                val call = calls.incrementAndGet()
                if (call == 1 || call == 4) return 0
                val limit = source.limit(); source.limit(source.position() + 1)
                return try { channel.write(source) } finally { source.limit(limit) }
            }
        }
        withServer(io = io, admitted = { acceptedAt.set(calls.get()); entries.add(it) }) { server ->
            connect(server).use { socket ->
                sendAll(socket)
                assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(socket, 4))
                nextEntry(); assertEquals(6, acceptedAt.get()); assertNoData(socket)
                val before = server.stats().loops.sumOf { it.readinessCallbacks }
                Thread.sleep(120)
                assertTrue(server.stats().loops.sumOf { it.readinessCallbacks } - before <= 2)
            }
        }
    }
    @Test fun zeroReadDoesNotDiscardBytesAndOtherClientsRemainFair() {
        val calls = AtomicInteger()
        val io = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer): Int = if (calls.incrementAndGet() == 1) 0 else channel.read(target)
            override fun write(channel: SocketChannel, source: ByteBuffer) = channel.write(source)
        }
        withServer(io = io) { server ->
            val sockets = (0 until 20).map { connect(server) }
            try {
                sockets.forEach { sendAll(it) }
                sockets.forEach { assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(it, 4)) }
                val ids = (0 until 20).map { nextEntry().session.sessionId }
                assertEquals(20, ids.distinct().size)
            } finally { sockets.forEach { it.close() } }
        }
    }
    @Test fun tcpCapacityFailureIsExplicitWhileUdpStillAdmitsAndReleasedTcpIsReusable() = capacityIsolation(1, 3)
    @Test fun udpCapacityFailureIsExplicitWhileTcpStillAdmitsAndReleasedUdpIsReusable() = capacityIsolation(3, 1)
    @Test fun authenticationCapacityRejectsBeforeReadThenRecovers() = withServer(limits = SocksSessionLimits(handshakes = 1)) { server ->
        connect(server).use { held ->
            await { server.stats().admission!!.handshakes.current == 1 }
            connect(server).use { eof(it) }
            assertEquals(1L, server.stats().admission!!.rejectedHandshakes)
            held.close()
            await { server.stats().admission!!.handshakes.current == 0 }
            connect(server).use { sendAll(it); read(it, 4); nextEntry() }
        }
    }
    @Test fun capacityFailureReplyHasDeadlineEvenWhenWritesRemainZero() {
        val refusedChannel = AtomicReference<SocketChannel>()
        val io = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
            override fun write(channel: SocketChannel, source: ByteBuffer): Int {
                if (source.remaining() == 10 && source.get(source.position() + 1).toInt() == 1) refusedChannel.set(channel)
                return if (channel === refusedChannel.get()) 0 else channel.write(source)
            }
        }
        withServer(io = io, limits = SocksSessionLimits(tcp = 1)) { server ->
            connect(server).use { held ->
                sendAll(held); read(held, 4); nextEntry()
                connect(server).use { refused -> sendAll(refused); read(refused, 4); eof(refused) }
                await { server.stats().admission!!.handshakes.current == 0 }
                assertEquals(1, server.stats().admission!!.tcp.current)
            }
        }
    }
    @Test fun credentialProviderExceptionClosesOnlyItsScopeAndReleasesLeases() = withServer(credentialsProvider = { throw IllegalStateException("fixture credentials") }) { server ->
        connect(server).use { socket -> socket.getOutputStream().write(greeting + auth); read(socket, 2); eof(socket) }
        await { server.stats().admission!!.handshakes.current == 0 }
        assertEquals(SocksNioServer.State.RUNNING, server.stats().state)
        assertEquals(1L, server.stats().loops.sumOf { it.callbackFailures })
    }
    @Test fun admissionCallbackExceptionClosesRetainedPayloadBuffersAndProtocolLease() {
        val seen = AtomicReference<SocksNioHandshake.AdmittedRequest>()
        withServer(admitted = { seen.set(it); throw IllegalStateException("fixture admission") }) { server ->
            connect(server).use { socket -> sendAll(socket, request, ByteArray(900)); read(socket, 4); eof(socket) }
            await { server.stats().admission!!.tcp.current == 0 }
            val entry = checkNotNull(seen.get())
            onOwner(entry) {
                assertEquals(SocksSession.State.CLOSED, it.session.snapshot().state)
                assertEquals(0, it.session.snapshot().bufferBytes)
                assertThrows(IllegalStateException::class.java) { it.readClient(ByteBuffer.allocate(1)) }
            }
        }
    }
    @Test fun downstreamCallbackExceptionAndWrongThreadReadsRespectUniqueOwnership() = withServer { server ->
        connect(server).use { socket ->
            sendAll(socket); read(socket, 4)
            val entry = nextEntry()
            assertThrows(IllegalStateException::class.java) { entry.readClient(ByteBuffer.allocate(1)) }
            onOwner(entry) { it.onReady { _, _ -> throw IllegalStateException("fixture downstream") }; it.interestOps(SelectionKey.OP_READ) }
            socket.getOutputStream().write(42); eof(socket)
            await { server.stats().admission!!.tcp.current == 0 }
        }
    }
    @Test fun stopWipesHeldPayloadAndAllSessionLeasesAndReplacementCannotReviveClosedKey() = withServer { server ->
        connect(server).use { socket ->
            sendAll(socket, request, ByteArray(900)); read(socket, 4)
            val entry = nextEntry()
            onOwner(entry) {
                assertTrue(it.bufferedClientBytes > 0)
                it.session.close()
                assertEquals(0, it.session.snapshot().bufferBytes)
                assertThrows(IllegalStateException::class.java) { it.onReady { _, _ -> } }
                assertThrows(IllegalStateException::class.java) { it.readClient(ByteBuffer.allocate(1)) }
            }
            eof(socket)
            assertTrue(server.stop())
        }
    }
    @Test fun stopDuringParsingAndManyRepeatedRunsLeaveNoContextsChannelsTimersOrBudgets() = withServer { server ->
        repeat(12) {
            connect(server).use { partial ->
                partial.getOutputStream().write(greeting + auth.copyOf(5))
                read(partial, 2)
                connect(server).use { active -> sendAll(active, request, ByteArray(200)); read(active, 4); nextEntry() }
                assertTrue(server.stop()); eof(partial); assertClean(server)
                server.start()
            }
        }
    }

    @Test fun ioReadAndWriteExceptionsCloseScopeAndLeaveServerAvailable() {
        for (failRead in listOf(true, false)) {
            val io = object : SocksNioHandshake.ClientIo {
                override fun read(channel: SocketChannel, target: ByteBuffer): Int {
                    if (failRead) throw java.io.IOException("fixture read")
                    return channel.read(target)
                }
                override fun write(channel: SocketChannel, source: ByteBuffer): Int = throw java.io.IOException("fixture write")
            }
            withServer(io = io) { server ->
                connect(server).use { socket -> socket.getOutputStream().write(greeting); eof(socket) }
                await { server.stats().admission!!.handshakes.current == 0 }
                assertEquals(SocksNioServer.State.RUNNING, server.stats().state)
            }
        }
    }
    @Test fun stopDuringZeroWriteBackoffClosesPendingControlBuffersAndRetryTimer() {
        val calls = AtomicInteger()
        withServer(io = zeroWrites(calls)) { server ->
            connect(server).use { socket ->
                socket.getOutputStream().write(greeting)
                await { calls.get() >= 3 }
                assertTrue(server.stop()); eof(socket); assertClean(server)
            }
        }
    }
    @Test fun stopRacesWithAdmittedCallbacksAndFragmentsWithoutDuplicateDelivery() = withServer { server ->
        repeat(20) {
            val socket = connect(server)
            val writer = Thread { try { sendAll(socket, request, ByteArray(2000)) } catch (_: java.io.IOException) { } }
            writer.start(); assertTrue(server.stop()); writer.join(2000); assertFalse(writer.isAlive)
            socket.close(); assertClean(server)
            val ids = entries.toList().map { entry -> entry.session.sessionId }
            assertEquals(ids.size, ids.distinct().size)
            entries.clear(); server.start()
        }
    }

    private fun capacityIsolation(fullCommand: Int, otherCommand: Int) = withServer(limits = SocksSessionLimits(tcp = 1, udp = 1)) { server ->
        connect(server).use { held ->
            sendAll(held, request.copy(command = fullCommand)); read(held, 4)
            val heldEntry = nextEntry()
            connect(server).use { refused ->
                sendAll(refused, request.copy(command = fullCommand))
                assertArrayEquals(byteArrayOf(5, 2, 1, 0) + SocksProtocol.encodeReply(1), read(refused, 14)); eof(refused)
            }
            connect(server).use { other ->
                sendAll(other, request.copy(command = otherCommand)); read(other, 4)
                val otherEntry = nextEntry()
                onOwner(otherEntry) { it.session.close() }; eof(other)
            }
            onOwner(heldEntry) { it.session.close() }; eof(held)
            await { server.stats().admission!!.tcp.current == 0 && server.stats().admission!!.udp.current == 0 }
            connect(server).use { reused -> sendAll(reused, request.copy(command = fullCommand)); read(reused, 4); nextEntry() }
            val stats = server.stats().admission!!
            assertEquals(1L, if (fullCommand == 1) stats.rejectedTcp else stats.rejectedUdp)
            assertEquals(0, stats.handshakes.current)
        }
    }
    private fun zeroWrites(calls: AtomicInteger) = object : SocksNioHandshake.ClientIo {
        override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
        override fun write(channel: SocketChannel, source: ByteBuffer): Int { calls.incrementAndGet(); return 0 }
    }
    private fun withServer(
        io: SocksNioHandshake.ClientIo = SocksNioHandshake.ClientIo.CHANNEL,
        limits: SocksSessionLimits = SocksSessionLimits(),
        clock: () -> Long = System::nanoTime,
        timeoutNanos: Long = SocksSessionAdmission.DEFAULT_HANDSHAKE_TIMEOUT_NANOS,
        credentialsProvider: () -> SocksCredentials? = { credentials },
        admitted: (SocksNioHandshake.AdmittedRequest) -> Unit = { entries.add(it) },
        action: (SocksNioServer) -> Unit
    ) {
        val server = SocksNioServer(SocksNioHandshake(credentialsProvider, admitted, io), sessionLimits = limits,
            sessionNanoClock = clock, handshakeTimeoutNanos = timeoutNanos)
        try { server.start(); action(server) } finally { assertTrue(server.stop()); assertClean(server) }
    }
    private fun assertClean(server: SocksNioServer) {
        val stats = server.stats()
        assertEquals(SocksNioServer.State.STOPPED, stats.state)
        assertEquals(0, stats.admission!!.handshakes.current); assertEquals(0, stats.admission.tcp.current); assertEquals(0, stats.admission.udp.current)
        assertEquals(listOf(0, 0), stats.admission.ownerLoads)
        stats.loops.forEach { assertEquals(0, it.channels); assertEquals(0, it.keys); assertEquals(0, it.resources); assertEquals(0, it.timers); assertEquals(0L, it.cleanupFailures) }
    }
    private fun connect(server: SocksNioServer) = Socket().also { it.soTimeout = 2500; it.tcpNoDelay = true; it.connect(InetSocketAddress("127.0.0.1", server.stats().port!!)) }
    private fun sendAll(socket: Socket, expected: SocksRequest = request, payload: ByteArray = byteArrayOf()) =
        socket.getOutputStream().write(greeting + auth + SocksProtocol.encodeRequest(expected) + payload)
    private fun read(socket: Socket, size: Int): ByteArray {
        val result = ByteArray(size); var offset = 0
        while (offset < size) { val count = socket.getInputStream().read(result, offset, size - offset); assertTrue("early EOF at $offset/$size", count > 0); offset += count }
        return result
    }
    private fun eof(socket: Socket) {
        try { assertEquals(-1, socket.getInputStream().read()) }
        catch (error: java.net.SocketException) {
            // Linux resets a socket closed with unread pipelined input. Both
            // terminal outcomes prove closure; a read timeout must still fail.
            assertTrue(error.toString(), error.message.orEmpty().contains("reset", ignoreCase = true))
        }
    }
    private fun assertNoData(socket: Socket) {
        val old = socket.soTimeout; socket.soTimeout = 100
        try { assertThrows(SocketTimeoutException::class.java) { socket.getInputStream().read() } } finally { socket.soTimeout = old }
    }
    private fun nextEntry(): SocksNioHandshake.AdmittedRequest { await { entries.isNotEmpty() }; return checkNotNull(entries.poll()) }
    private fun onOwner(entry: SocksNioHandshake.AdmittedRequest, action: (SocksNioHandshake.AdmittedRequest) -> Unit) {
        val done = CountDownLatch(1); val error = AtomicReference<Throwable>()
        assertEquals(SocksEventLoop.Submission.ACCEPTED, entry.session.owner.submit {
            try { action(entry) } catch (caught: Throwable) { error.set(caught) } finally { done.countDown() }
        })
        assertTrue(done.await(3, TimeUnit.SECONDS)); error.get()?.let { throw it }
    }
    private fun collect(entry: SocksNioHandshake.AdmittedRequest, size: Int, chunk: Int): ByteArray {
        val result = ByteArrayOutputStream(size); val done = CountDownLatch(1); val error = AtomicReference<Throwable>()
        onOwner(entry) { client ->
            fun drain() {
                try {
                    // Test relay's bounded fairness budget; never loops indefinitely on read(0).
                    var budget = 64 * 1024
                    while (result.size() < size && budget > 0) {
                        val target = ByteBuffer.allocate(minOf(chunk, size - result.size()))
                        val count = client.readClient(target)
                        if (count <= 0) break
                        result.write(target.array(), 0, count); budget -= count
                    }
                    if (result.size() == size) { client.interestOps(0); done.countDown() }
                } catch (caught: Throwable) { error.set(caught); client.interestOps(0); done.countDown() }
            }
            client.onReady { _, _ -> drain() }; client.interestOps(SelectionKey.OP_READ); drain()
        }
        assertTrue("payload wait ${result.size()}/$size", done.await(5, TimeUnit.SECONDS)); error.get()?.let { throw it }
        return result.toByteArray()
    }
    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (!condition()) { assertTrue("condition deadline", System.nanoTime() < deadline); Thread.sleep(2) }
    }
}
