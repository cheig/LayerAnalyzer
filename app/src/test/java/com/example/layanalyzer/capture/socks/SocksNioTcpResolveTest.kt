// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.UnknownHostException
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class SocksNioTcpResolveTest {
    private val ipv4 = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val ipv6 = InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 })
    private val credentials = SocksCredentials.of("User", "Password")
    private val handshake = byteArrayOf(5, 1, 2, 1, 4) + "User".toByteArray() + byteArrayOf(8) + "Password".toByteArray()

    @Test fun ipv4AndIpv6LiteralsNeverCreateDnsWorkers() {
        listOf(ipv4, ipv6).forEach { address ->
            ServerSocket(0, 8, address).use { target ->
                fixture(lookup = { fail("literal must bypass DNS"); emptyArray() }).use { f ->
                    f.client(target.localPort, SocksDestination.Ip(address)).use { client ->
                        assertEquals(0, reply(client)[1].toInt())
                        target.accept().close()
                        assertEquals(0, f.resolver.stats().workers); assertEquals(0L, f.resolver.stats().lookups)
                    }
                }
            }
        }
    }

    @Test fun frozenLookupRunsOffOwnerAndPreservesPipelinedPayloadThroughRelay() {
        ServerSocket(0, 8, ipv4).use { target ->
            val calls = ConcurrentLinkedQueue<String>()
            fixture(lookup = { host -> calls.add("${Thread.currentThread().name}:$host"); arrayOf(ipv4) }).use { f ->
                val payload = ByteArray(4096) { (it * 17).toByte() }
                f.client(target.localPort, payload = payload).use { client ->
                    assertEquals(0, reply(client)[1].toInt())
                    target.accept().use { remote ->
                        remote.soTimeout = 3000
                        assertArrayEquals(payload, read(remote, payload.size))
                        remote.getOutputStream().write(payload)
                        assertArrayEquals(payload, read(client, payload.size))
                    }
                    assertEquals(1, calls.size); assertTrue(calls.first().startsWith("SocksDns-"))
                    assertTrue(calls.first().endsWith(":target.test"))
                }
            }
        }
    }

    @Test fun sameScopeDeduplicatesAcrossSessionOwnersAndConnectsBoth() {
        val release = CountDownLatch(1); val started = CountDownLatch(1)
        try {
            ServerSocket(0, 8, ipv4).use { target ->
                fixture(lookup = { started.countDown(); awaitLatch(release); arrayOf(ipv4) }).use { f ->
                    f.client(target.localPort).use { first ->
                        awaitLatch(started)
                        f.client(target.localPort).use { second ->
                            await { f.resolver.stats().merged == 1L }
                            release.countDown()
                            assertEquals(0, reply(first)[1].toInt()); assertEquals(0, reply(second)[1].toInt())
                            target.accept().close(); target.accept().close()
                            assertEquals(1L, f.resolver.stats().lookups)
                        }
                    }
                }
            }
        } finally { release.countDown() }
    }

    @Test fun exceptionEmptyAndOversizeDnsReturnFiniteFailureWithoutOpeningUpstream() {
        val lookups: List<(String) -> Array<InetAddress>> = listOf(
            { throw UnknownHostException("fixture") }, { emptyArray() }, { Array(65) { ipv4 } })
        lookups.forEach { lookup -> fixture(lookup = lookup).use { f ->
            f.client(80).use(::assertFailureAndEof)
            assertEquals(0, f.channels.size); assertEquals(1L, f.resolver.stats().failed)
        } }
    }

    @Test fun dnsTimeoutSendsFailureAndLateResultCannotConnect() {
        val release = CountDownLatch(1); val started = CountDownLatch(1)
        try {
            fixture(lookup = { started.countDown(); awaitLatch(release); arrayOf(ipv4) }, dnsTimeout = 80_000_000).use { f ->
                f.client(80).use { client ->
                    awaitLatch(started); assertFailureAndEof(client)
                    assertEquals(1L, f.resolver.stats().timedOut)
                    assertEquals(0, f.resolver.stats().subscribers); assertEquals(1, f.resolver.stats().activeLookups)
                    assertEquals(0, f.channels.size)
                    release.countDown(); await { f.resolver.stats().activeLookups == 0 }
                    assertEquals(1L, f.resolver.stats().abandonedResults); assertEquals(0, f.channels.size)
                }
            }
        } finally { release.countDown() }
    }

    @Test fun totalEstablishmentDeadlineIncludesDnsAndDoesNotRestartAtConnect() {
        val clock = AtomicLong(System.nanoTime())
        val release = CountDownLatch(1); val started = CountDownLatch(1)
        try {
            fixture(lookup = { started.countDown(); awaitLatch(release); arrayOf(ipv4) }, clock = clock::get,
                prepare = { clock.addAndGet(7_000_000_000) }).use { f ->
                f.client(80).use { client ->
                    awaitLatch(started)
                    val entry = f.entry()
                    var deadline = 0L
                    f.owner(entry) {
                        assertEquals(SocksSession.State.RESOLVING, it.session.snapshot().state)
                        deadline = it.session.snapshot().deadlineNanos!!
                    }
                    clock.addAndGet(9_000_000_000) // DNS uses 9s of 15s, below its 10s subdeadline.
                    release.countDown()
                    assertFailureAndEof(client) // prepare crosses original 15s; no connect is sent.
                    assertEquals(1, f.channels.size); assertEquals(0, f.connectCalls.get())
                    assertTrue(clock.get() - deadline > 0)
                    f.owner(entry) { assertTrue(it.session.snapshot().closeCause is SocksSession.DeadlineExceededException) }
                }
            }
        } finally { release.countDown() }
    }

    @Test fun queueWaitCountsTowardDnsSubdeadlineAndTimedOutQueuedLookupNeverRuns() {
        val release = CountDownLatch(1); val started = CountDownLatch(1); val names = ConcurrentLinkedQueue<String>()
        try {
            fixture(lookup = { names.add(it); started.countDown(); awaitLatch(release); arrayOf(ipv4) },
                limits = SocksResolver.Limits(workers = 1), dnsTimeout = 120_000_000).use { f ->
                f.client(80, SocksDestination.Domain("first.test")).use { first ->
                    awaitLatch(started)
                    f.client(80, SocksDestination.Domain("queued.test")).use { queued ->
                        await { f.resolver.stats().queuedQueries == 1 }
                        assertFailureAndEof(first); assertFailureAndEof(queued)
                        assertEquals(0, f.resolver.stats().queuedQueries)
                        assertEquals(2L, f.resolver.stats().timedOut)
                        release.countDown(); await { f.resolver.stats().activeLookups == 0 }
                        assertEquals(listOf("first.test"), names.toList())
                    }
                }
            }
        } finally { release.countDown() }
    }

    @Test fun fullQueueImmediatelyFailsNewSessionAndPreservesExistingWork() {
        val release = CountDownLatch(1); val started = CountDownLatch(1)
        try {
            fixture(lookup = { started.countDown(); awaitLatch(release); arrayOf(ipv4) },
                limits = SocksResolver.Limits(workers = 1, queuedQueries = 1)).use { f ->
                f.client(80, SocksDestination.Domain("running.test")).use { _ ->
                    awaitLatch(started)
                    f.client(80, SocksDestination.Domain("queued.test")).use { _ ->
                        await { f.resolver.stats().queuedQueries == 1 }
                        f.client(80, SocksDestination.Domain("overflow.test")).use(::assertFailureAndEof)
                        assertEquals(1, f.resolver.stats().activeLookups); assertEquals(1, f.resolver.stats().queuedQueries)
                        assertEquals(2, f.resolver.stats().subscribers); assertEquals(1L, f.resolver.stats().rejected)
                        f.scope.close(); release.countDown()
                    }
                }
            }
        } finally { release.countDown() }
    }

    @Test fun closingSessionImmediatelyDetachesItsSubscriptionWithoutWaitingForLookup() {
        val release = CountDownLatch(1); val started = CountDownLatch(1)
        try {
            fixture(lookup = { started.countDown(); awaitLatch(release); arrayOf(ipv4) }).use { f ->
                f.client(80).use { client ->
                    awaitLatch(started); val entry = f.entry()
                    f.owner(entry) { it.session.close() }
                    assertEquals(-1, client.getInputStream().read())
                    assertEquals(0, f.resolver.stats().subscribers); assertEquals(1, f.resolver.stats().activeLookups)
                    release.countDown(); await { f.resolver.stats().activeLookups == 0 }
                    assertEquals(0, f.channels.size)
                }
            }
        } finally { release.countDown() }
    }

    @Test fun queuedCompletionIsDiscardedAfterSessionClose() {
        val dnsRelease = CountDownLatch(1); val started = CountDownLatch(1); val ownerRelease = CountDownLatch(1)
        try {
            fixture(lookup = { started.countDown(); awaitLatch(dnsRelease); arrayOf(ipv4) }).use { f ->
                f.client(80).use { client ->
                    awaitLatch(started); val entry = f.entry(); val blocked = CountDownLatch(1)
                    assertEquals(SocksEventLoop.Submission.ACCEPTED, entry.session.owner.submit {
                        blocked.countDown(); awaitLatch(ownerRelease); entry.session.close()
                    })
                    awaitLatch(blocked); dnsRelease.countDown()
                    await { entry.session.owner.stats().completions == 1 }
                    ownerRelease.countDown(); assertEquals(-1, client.getInputStream().read())
                    await { f.resolver.stats().discardedCompletions == 1L }
                    assertEquals(0, f.channels.size)
                }
            }
        } finally { dnsRelease.countDown(); ownerRelease.countDown() }
    }

    @Test fun networkInvalidationRejectsAlreadyQueuedSuccessOnOwner() {
        val dnsRelease = CountDownLatch(1); val started = CountDownLatch(1); val ownerRelease = CountDownLatch(1)
        try {
            fixture(lookup = { started.countDown(); awaitLatch(dnsRelease); arrayOf(ipv4) }).use { f ->
                f.client(80).use { client ->
                    awaitLatch(started); val entry = f.entry(); val blocked = CountDownLatch(1)
                    entry.session.owner.submit { blocked.countDown(); awaitLatch(ownerRelease) }
                    awaitLatch(blocked); dnsRelease.countDown(); await { entry.session.owner.stats().completions == 1 }
                    f.scope.close(); ownerRelease.countDown()
                    assertEquals(-1, client.getInputStream().read())
                    await { f.resolver.stats().discardedCompletions == 1L }
                    assertEquals(0, f.channels.size)
                }
            }
        } finally { dnsRelease.countDown(); ownerRelease.countDown() }
    }

    @Test fun completionQueueRejectionLeavesOwnerTimerToSendFiniteFailure() {
        val dnsRelease = CountDownLatch(1); val started = CountDownLatch(1); val ownerRelease = CountDownLatch(1)
        try {
            fixture(lookup = { started.countDown(); awaitLatch(dnsRelease); arrayOf(ipv4) }, dnsTimeout = 200_000_000,
                config = SocksEventLoopConfig(completionCapacity = 1, completionsPerTurn = 1)).use { f ->
                f.client(80).use { client ->
                    awaitLatch(started); val entry = f.entry(); val blocked = CountDownLatch(1)
                    entry.session.owner.submit { blocked.countDown(); awaitLatch(ownerRelease) }
                    awaitLatch(blocked)
                    assertEquals(SocksEventLoop.Submission.ACCEPTED, entry.session.owner.complete {})
                    dnsRelease.countDown(); await { f.resolver.stats().rejectedCompletions == 1L }
                    ownerRelease.countDown(); assertFailureAndEof(client)
                    assertEquals(1L, f.resolver.stats().timedOut); assertEquals(1L, f.resolver.stats().discardedCompletions)
                    assertEquals(0, f.channels.size)
                }
            }
        } finally { dnsRelease.countDown(); ownerRelease.countDown() }
    }

    @Test fun expiredQueuedCompletionUsesDnsFailureReplyAndCannotReviveOperation() {
        val clock = AtomicLong(System.nanoTime())
        val dnsRelease = CountDownLatch(1); val started = CountDownLatch(1); val ownerRelease = CountDownLatch(1)
        try {
            fixture(lookup = { started.countDown(); awaitLatch(dnsRelease); arrayOf(ipv4) }, clock = clock::get).use { f ->
                f.client(80).use { client ->
                    awaitLatch(started); val entry = f.entry(); val blocked = CountDownLatch(1)
                    entry.session.owner.submit { blocked.countDown(); awaitLatch(ownerRelease) }
                    awaitLatch(blocked); dnsRelease.countDown(); await { entry.session.owner.stats().completions == 1 }
                    clock.addAndGet(11_000_000_000); ownerRelease.countDown()
                    assertFailureAndEof(client)
                    assertEquals(1L, f.resolver.stats().timedOut); assertEquals(1L, f.resolver.stats().discardedCompletions)
                    assertEquals(0, f.channels.size)
                }
            }
        } finally { dnsRelease.countDown(); ownerRelease.countDown() }
    }

    @Test fun generationMismatchAndClosedScopeFailBeforeLookupOrConnect() {
        fixture(generation = 2).use { f ->
            f.client(80).use(::assertFailureAndEof)
            assertEquals(0L, f.resolver.stats().lookups); assertEquals(0, f.channels.size)
        }
        fixture().use { f ->
            f.scope.close()
            f.client(80, SocksDestination.Ip(ipv4)).use(::assertFailureAndEof)
            assertEquals(0, f.channels.size)
        }
    }

    @Test fun stoppedCaptureReleasesSessionsWhileSystemLookupStillOccupiesSharedWorker() {
        val release = CountDownLatch(1); val started = CountDownLatch(1)
        try {
            fixture(lookup = {
                started.countDown()
                while (release.count != 0L) try { release.await() } catch (_: InterruptedException) { }
                arrayOf(ipv4)
            }).use { f ->
                f.client(80).use { client ->
                    awaitLatch(started)
                    val start = System.nanoTime(); f.scope.close(); assertTrue(f.server.stop())
                    assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 500)
                    assertEquals(-1, client.getInputStream().read())
                    assertEquals(0, f.resolver.stats().subscribers); assertEquals(1, f.resolver.stats().activeLookups)
                    assertEquals(0, f.server.stats().admission!!.tcp.current)
                    release.countDown(); await { f.resolver.stats().activeLookups == 0 }
                    assertEquals(0, f.channels.size)
                }
            }
        } finally { release.countDown() }
    }

    @Test fun dnsFailureReplyWithZeroWritesStillClosesAtItsOwnDeadline() {
        val writes = AtomicInteger()
        val io = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
            override fun write(channel: SocketChannel, source: ByteBuffer): Int =
                if (source.remaining() > 2) { writes.incrementAndGet(); 0 } else channel.write(source)
        }
        fixture(lookup = { emptyArray() }, replyTimeout = 60_000_000, clientIo = io).use { f ->
            f.client(80).use { client -> assertEquals(-1, client.getInputStream().read()) }
            assertTrue(writes.get() > 0); assertTrue(writes.get() < 200)
            assertEquals(0, f.channels.size)
        }
    }

    private fun fixture(lookup: (String) -> Array<InetAddress> = { arrayOf(ipv4) },
        limits: SocksResolver.Limits = SocksResolver.Limits(), dnsTimeout: Long = SocksNioTcpResolve.DNS_TIMEOUT_NANOS,
        clock: () -> Long = System::nanoTime, prepare: (Socket) -> Unit = {}, generation: Long = 1,
        config: SocksEventLoopConfig = SocksEventLoopConfig(),
        replyTimeout: Long = SocksNioTcpConnect.REPLY_TIMEOUT_NANOS,
        clientIo: SocksNioHandshake.ClientIo = SocksNioHandshake.ClientIo.CHANNEL
    ) = Fixture(lookup, limits, dnsTimeout, clock, prepare, generation, config, replyTimeout, clientIo)

    private inner class Fixture(lookup: (String) -> Array<InetAddress>, limits: SocksResolver.Limits,
        dnsTimeout: Long, clock: () -> Long, prepare: (Socket) -> Unit, generation: Long,
        config: SocksEventLoopConfig, replyTimeout: Long, clientIo: SocksNioHandshake.ClientIo) : AutoCloseable {
        val resolver = SocksResolver.forTest(limits)
        val scope = resolver.newScope(generation, 7, lookup)
        val channels = ConcurrentLinkedQueue<SocketChannel>()
        val entries = ConcurrentLinkedQueue<SocksNioHandshake.AdmittedRequest>()
        val connectCalls = AtomicInteger()
        val relay = TcpRelay(SocksTcpBufferBudget())
        val connector = SocksNioTcpConnect(prepare, { relay.start(it) }, replyTimeoutNanos = replyTimeout,
            io = object : SocksNioTcpConnect.ConnectIo {
                override fun open() = SocketChannel.open().also { channels.add(it) }
                override fun connect(channel: SocketChannel, address: InetSocketAddress): Boolean {
                    connectCalls.incrementAndGet(); return channel.connect(address)
                }
            })
        val resolve = SocksNioTcpResolve(scope, connector, dnsTimeoutNanos = dnsTimeout)
        val server = SocksNioServer(SocksNioHandshake({ credentials }, {
            entries.add(it)
            if (relay.reserve(it.session)) resolve.connect(it) else connector.fail(it, IllegalStateException("buffer budget"))
        }, clientIo), config = config, sessionNanoClock = clock).also { it.start() }

        fun client(port: Int, destination: SocksDestination = SocksDestination.Domain("target.test"),
            payload: ByteArray = byteArrayOf()): Socket = Socket().also {
            it.soTimeout = 3000; it.connect(InetSocketAddress(ipv4, server.stats().port!!))
            it.getOutputStream().write(handshake + SocksProtocol.encodeRequest(SocksRequest(1, destination, port)) + payload)
            assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(it, 4))
        }
        fun entry(): SocksNioHandshake.AdmittedRequest { await { entries.isNotEmpty() }; return entries.poll()!! }
        fun owner(entry: SocksNioHandshake.AdmittedRequest, action: (SocksNioHandshake.AdmittedRequest) -> Unit) {
            val done = CountDownLatch(1); val error = AtomicReference<Throwable>()
            assertEquals(SocksEventLoop.Submission.ACCEPTED, entry.session.owner.submit {
                try { action(entry) } catch (caught: Throwable) { error.set(caught) } finally { done.countDown() }
            })
            awaitLatch(done); error.get()?.let { throw it }
        }
        override fun close() {
            scope.close(); assertTrue(server.stop())
            val stats = server.stats()
            assertEquals(0, stats.admission!!.handshakes.current); assertEquals(0, stats.admission.tcp.current)
            assertEquals(0, stats.admission.udp.current); assertEquals(listOf(0, 0), stats.admission.ownerLoads)
            stats.loops.forEach {
                assertEquals(0, it.channels); assertEquals(0, it.keys); assertEquals(0, it.resources)
                assertEquals(0, it.timers); assertEquals(0L, it.cleanupFailures)
            }
            assertEquals(0, resolver.stats().subscribers); assertTrue(channels.none { it.isOpen })
            assertTrue(resolver.shutdownForTest())
        }
    }

    private fun reply(socket: Socket): ByteArray {
        val header = read(socket, 4)
        assertEquals(5, header[0].toInt())
        return header + read(socket, if (header[3].toInt() == 1) 6 else 18)
    }
    private fun assertFailureAndEof(socket: Socket) {
        assertArrayEquals(SocksProtocol.encodeReply(1), reply(socket)); assertEquals(-1, socket.getInputStream().read())
    }
    private fun read(socket: Socket, size: Int): ByteArray {
        val bytes = ByteArray(size); var offset = 0
        while (offset < size) { val count = socket.getInputStream().read(bytes, offset, size - offset); assertTrue(count > 0); offset += count }
        return bytes
    }
    private fun awaitLatch(latch: CountDownLatch) { assertTrue(latch.await(3, TimeUnit.SECONDS)) }
    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (!condition()) { assertTrue("condition deadline", System.nanoTime() < deadline); Thread.sleep(2) }
    }
}
