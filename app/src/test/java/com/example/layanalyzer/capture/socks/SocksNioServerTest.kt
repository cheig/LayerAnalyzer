// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksSessionLimits
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.nio.ByteBuffer
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class SocksNioServerTest {
    @Test
    fun concurrentStopCannotPublishCleanupOrRestartUntilRunStopHookFinishes() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val hooks = AtomicInteger()
        val server = SocksNioServer(Handler(), onRunStopping = {
            if (hooks.incrementAndGet() == 1) {
                entered.countDown()
                assertTrue(release.await(3, TimeUnit.SECONDS))
            }
        })
        val result = AtomicReference<Boolean>()
        server.start()
        val stopper = Thread { result.set(server.stop()) }.apply { start() }
        try {
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            assertFalse(server.stop(30))
            assertEquals(SocksNioServer.State.STOPPING, server.stats().state)
            assertThrows(IllegalStateException::class.java) { server.start() }
            release.countDown()
            stopper.join(3000)
            assertFalse(stopper.isAlive)
            assertEquals(true, result.get())
            assertEquals(SocksNioServer.State.STOPPED, server.stats().state)
            server.start()
            assertEquals(2L, server.stats().captureGeneration)
            assertFalse(server.stop(expectedGeneration = 1))
            assertEquals(SocksNioServer.State.RUNNING, server.stats().state)
        } finally { release.countDown(); stopper.join(3000); server.stop() }
        assertEquals(2, hooks.get())
    }

    private data class Entry(val session: SocksSession, val registration: SocksEventLoop.Registration)
    private class Handler(
        val opened: (SocksSession, SocksEventLoop.Registration) -> Unit = { _, _ -> },
        val ready: (SocksSession, SocksEventLoop.Registration, Int) -> Unit = { session, registration, _ ->
            if ((registration.channel as SocketChannel).read(ByteBuffer.allocate(32)) < 0) session.close()
        }
    ) : SocksNioServer.SessionHandler {
        val entries = ConcurrentLinkedQueue<Entry>()
        override fun onSession(session: SocksSession, registration: SocksEventLoop.Registration) {
            entries.add(Entry(session, registration))
            opened(session, registration)
        }
        override fun onReady(session: SocksSession, registration: SocksEventLoop.Registration, ops: Int) =
            ready(session, registration, ops)
    }

    @Test
    fun loopbackListenerPublishesRegisteredPortAndHandsOffActualNonblockingChannel() {
        val ready = CountDownLatch(1)
        val handler = Handler(ready = { session, registration, _ ->
            assertTrue(session.owner.inEventLoop())
            assertFalse(registration.channel.isBlocking)
            val channel = registration.channel as SocketChannel
            assertTrue((channel.remoteAddress as InetSocketAddress).address.isLoopbackAddress)
            val data = ByteBuffer.allocate(1)
            assertEquals(1, channel.read(data))
            assertEquals(42.toByte(), data.get(0))
            ready.countDown()
            session.close()
        })
        withServer(handler) { server ->
            val port = server.start()
            assertEquals(SocksNioServer.State.RUNNING, server.stats().state)
            assertTrue(server.stats().listenerRegistered)
            connect(port).use { it.getOutputStream().write(42); assertTrue(ready.await(2, TimeUnit.SECONDS)); eof(it) }
            await { server.stats().admission!!.handshakes.current == 0 }
            assertEquals(listOf(0, 0), server.stats().admission!!.ownerLoads)
        }
    }

    @Test
    fun repeatedStartStopUsesFreshGenerationAndReleasesPortAndResources() = withServer { server ->
        repeat(8) { index ->
            val port = server.start()
            connect(port).use {
                await { server.stats().admission!!.handshakes.current == 1 }
                assertTrue(server.stop())
                eof(it)
            }
            assertEquals((index + 1).toLong(), server.stats().captureGeneration)
            assertClean(server)
            ServerSocketChannel.open().use { it.bind(loopback(port)) }
            assertTrue(server.stop(0))
        }
    }

    @Test
    fun duplicateStartFailsWithoutReplacingRunningGeneration() = withServer { server ->
        val port = server.start()
        assertThrows(IllegalStateException::class.java) { server.start() }
        assertEquals(port, server.stats().port)
        assertEquals(1L, server.stats().captureGeneration)
        connect(port).use { await { server.stats().acceptedClients == 1L } }
    }

    @Test
    fun stoppingNewServerIsIdempotentAndAllowsFirstStart() = withServer { server ->
        assertTrue(server.stop(0)); assertTrue(server.stop())
        assertEquals(SocksNioServer.State.NEW, server.stats().state)
        server.start()
    }

    @Test
    fun bindsOnlyLoopbackAndExplicitPort() {
        val listener = AtomicReference<ServerSocketChannel>()
        val server = SocksNioServer(Handler(), listenerFactory = { ServerSocketChannel.open().also { listener.set(it) } })
        try {
            val port = server.start()
            assertEquals(loopback(port), listener.get().localAddress)
            assertTrue(server.stop())
            assertEquals(port, server.start(port))
        } finally { assertTrue(server.stop()) }
        assertFalse(listener.get().isOpen)
    }

    @Test
    fun occupiedPortFailsThenSameAssemblyCanRestartWithoutLeaks() = withServer { server ->
        ServerSocketChannel.open().use { occupied ->
            occupied.bind(loopback(0))
            assertThrows(IOException::class.java) { server.start((occupied.localAddress as InetSocketAddress).port) }
            assertTrue(server.stop()); assertClean(server)
            assertNotNull(server.stats().failure)
        }
        server.start()
        assertNull(server.stats().failure)
        assertEquals(2L, server.stats().captureGeneration)
    }

    @Test
    fun closedListenerFactoryAndSelectorFailuresCleanAllOpenedResources() {
        val selectors = ConcurrentLinkedQueue<Selector>()
        val server = SocksNioServer(Handler(), listenerFactory = {
            ServerSocketChannel.open().also { it.close() }
        }, selectorFactory = { Selector.open().also { selectors.add(it) } })
        try {
            assertThrows(IllegalStateException::class.java) { server.start() }
            assertTrue(server.stop()); assertClean(server)
            assertTrue(selectors.all { !it.isOpen })
        } finally { server.close() }
    }

    @Test
    fun secondSelectorStartupFailureStopsFirstLoopAndNeverCreatesListener() {
        val selectors = ConcurrentLinkedQueue<Selector>()
        val calls = AtomicInteger()
        val server = SocksNioServer(Handler(), listenerFactory = { calls.incrementAndGet(); ServerSocketChannel.open() },
            selectorFactory = { index -> if (index == 1) throw IOException("second selector")
                else Selector.open().also { selectors.add(it) } })
        try {
            assertThrows(IOException::class.java) { server.start() }
            assertTrue(server.stop()); assertClean(server)
            assertEquals(0, calls.get()); assertTrue(selectors.all { !it.isOpen })
        } finally { server.close() }
    }

    @Test
    fun secondThreadStartupFailureClosesBothSelectorsWithoutPublishingPort() {
        val selectors = ConcurrentLinkedQueue<Selector>()
        val server = SocksNioServer(Handler(), selectorFactory = { Selector.open().also { selectors.add(it) } },
            threadFactory = { task, name ->
                if (name.endsWith("1")) object : Thread(task, name) {
                    override fun start() { throw IllegalStateException("thread start failed") }
                } else Thread(task, name)
            })
        try {
            assertThrows(IllegalStateException::class.java) { server.start() }
            assertTrue(server.stop()); assertClean(server)
            assertTrue(selectors.all { !it.isOpen }); assertNotNull(server.stats().failure)
        } finally { server.close() }
    }

    @Test
    fun listenerScopeFailureDuringAcceptedChannelCreationSupervisesBothLoops() {
        val server = SocksNioServer(Handler(), sessionNanoClock = { throw IllegalStateException("admission clock failed") })
        try {
            connect(server.start()).use {
                await { server.stats().state == SocksNioServer.State.STOPPED }
                eof(it); assertClean(server)
                assertEquals("admission clock failed", server.stats().failure!!.message)
            }
        } finally { server.close() }
    }

    @Test
    fun startStopPublicationRaceNeverLeavesPublishedPortOrLeaksAndCanRestart() = withServer { server ->
        repeat(20) {
            val started = AtomicReference<Int>()
            val error = AtomicReference<Throwable>()
            val worker = Thread { try { started.set(server.start()) } catch (caught: Throwable) { error.set(caught) } }
            worker.start()
            await { server.stats().captureGeneration == (it + 1).toLong() }
            assertTrue(server.stop())
            worker.join(2_000); assertFalse(worker.isAlive)
            assertTrue(started.get() != null || error.get() is IllegalStateException)
            assertClean(server)
        }
    }

    @Test
    fun listenerRegistrationResourceFailureNeverPublishesPortAndStopsPeers() {
        lateinit var server: SocksNioServer
        server = SocksNioServer(Handler(), config = SocksEventLoopConfig(resourceCapacity = 1),
            listenerFactory = {
                onLoop(server.loop(0)) { server.loop(0).openResource() }
                ServerSocketChannel.open()
            })
        try {
            assertThrows(IllegalStateException::class.java) { server.start() }
            assertTrue(server.stop()); assertClean(server)
            assertNull(server.stats().port)
            assertNotNull(server.stats().failure)
        } finally { server.close() }
    }

    @Test
    fun listenerQueueRejectionLeavesStartupChannelCallerOwnedAndClosesIt() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val listener = AtomicReference<ServerSocketChannel>()
        lateinit var server: SocksNioServer
        server = SocksNioServer(Handler(), config = smallConfig(), listenerFactory = {
            val loop = server.loop(0)
            accepted(loop.submit { entered.countDown(); release.await(3, TimeUnit.SECONDS) })
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            accepted(loop.submit {})
            ServerSocketChannel.open().also { listener.set(it) }
        })
        try {
            assertThrows(IllegalStateException::class.java) { server.start(timeoutMillis = 100) }
            assertFalse(listener.get().isOpen)
            assertNull(server.stats().port)
            assertFalse(server.stop(0))
        } finally { release.countDown(); assertTrue(server.stop()); assertClean(server) }
    }

    @Test
    fun registrationTimeoutHasBoundedTotalDeadlineAndEventuallyOwnerClosesListener() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val listener = AtomicReference<ServerSocketChannel>()
        lateinit var server: SocksNioServer
        server = SocksNioServer(Handler(), listenerFactory = {
            accepted(server.loop(0).submit { entered.countDown(); release.await(3, TimeUnit.SECONDS) })
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            ServerSocketChannel.open().also { listener.set(it) }
        })
        try {
            val start = System.nanoTime()
            assertThrows(IllegalStateException::class.java) { server.start(timeoutMillis = 100) }
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 800)
            assertTrue(listener.get().isOpen) // accepted ownership must stay with blocked owner
            assertFalse(server.stop(0))
        } finally {
            release.countDown(); assertTrue(server.stop()); assertClean(server)
            assertFalse(listener.get().isOpen)
        }
    }

    @Test
    fun stopDuringSlowListenerFactoryReturnsBoundedlyAndClosesLateChannel() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val listener = AtomicReference<ServerSocketChannel>()
        val server = SocksNioServer(Handler(), listenerFactory = {
            entered.countDown(); release.await(3, TimeUnit.SECONDS)
            ServerSocketChannel.open().also { listener.set(it) }
        })
        val error = AtomicReference<Throwable>()
        val worker = Thread { try { server.start() } catch (caught: Throwable) { error.set(caught) } }
        try {
            worker.start(); assertTrue(entered.await(2, TimeUnit.SECONDS))
            val start = System.nanoTime()
            assertFalse(server.stop(100))
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 800)
            assertNull(server.stats().port)
            assertThrows(IllegalStateException::class.java) { server.start() }
        } finally {
            release.countDown(); worker.join(2_000); assertFalse(worker.isAlive)
            assertNotNull(error.get()); assertTrue(server.stop()); assertClean(server)
            assertFalse(listener.get().isOpen)
        }
    }

    @Test
    fun stopDuringSlowSelectorFactoryClosesLateSelectorWithoutListener() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val selector = AtomicReference<Selector>()
        val calls = AtomicInteger()
        val server = SocksNioServer(Handler(), selectorFactory = { index ->
            if (index == 0) { entered.countDown(); release.await(3, TimeUnit.SECONDS) }
            Selector.open().also { selector.set(it) }
        }, listenerFactory = { calls.incrementAndGet(); ServerSocketChannel.open() })
        val worker = Thread { try { server.start() } catch (_: IllegalStateException) {} }
        try {
            worker.start(); assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertFalse(server.stop(100)); assertNull(server.stats().port)
        } finally {
            release.countDown(); worker.join(2_000); assertFalse(worker.isAlive)
            assertTrue(server.stop()); assertClean(server)
            assertFalse(selector.get().isOpen); assertEquals(0, calls.get())
        }
    }

    @Test
    fun authenticationFullDrainsRealBacklogAndSlotCanBeReusedWithoutIdleSpin() {
        val handler = Handler()
        val server = SocksNioServer(handler, sessionLimits = SocksSessionLimits(handshakes = 2))
        val held = mutableListOf<Socket>()
        try {
            val port = server.start()
            repeat(2) { held.add(connect(port)) }
            await { handler.entries.size == 2 }
            val rejected = List(40) { connect(port) }
            try { rejected.forEach { eof(it) } } finally { rejected.forEach { it.close() } }
            await { server.stats().rejectedAdmissions == 40L }
            assertEquals(2, server.stats().admission!!.handshakes.peak)
            assertEquals(40L, server.stats().admission!!.rejectedHandshakes)
            idleStable(server)
            val first = checkNotNull(handler.entries.peek())
            onLoop(first.session.owner) { first.session.close() }
            await { server.stats().admission!!.handshakes.current == 1 }
            connect(port).use { await { handler.entries.size == 3 }; assertEquals(2, server.stats().admission!!.handshakes.current) }
        } finally { held.forEach { it.close() }; assertTrue(server.stop()); assertClean(server) }
    }

    @Test
    fun defaultAuthenticationHardCap64ThenRejectsNextRealClient() = withServer { server ->
        val port = server.start()
        val clients = List(64) { index ->
            connect(port).also { await { server.stats().admission!!.handshakes.current == index + 1 } }
        }
        try {
            await { server.stats().admission!!.handshakes.current == 64 }
            connect(port).use { eof(it) }
            assertEquals(64, server.stats().admission!!.handshakes.peak)
            assertEquals(listOf(32, 32), server.stats().admission!!.ownerLoads)
            assertTrue(server.stop()); clients.forEach { eof(it) }; assertClean(server)
        } finally { clients.forEach { it.close() } }
    }

    @Test
    fun loadAwareAssignmentCountsAdmittedSessionsAndRotatesTies() {
        val handler = Handler(opened = { session, _ ->
            session.enterAuth(); session.enterRequest()
            assertTrue(session.admitProtocol(SocksSessionAdmission.Protocol.TCP))
        })
        withServer(handler) { server ->
            val port = server.start()
            val clients = List(6) { connect(port) }
            try {
                await { handler.entries.size == 6 && server.stats().admission!!.tcp.current == 6 }
                assertEquals(listOf(3, 3), server.stats().admission!!.ownerLoads)
                val owner0 = handler.entries.filter { it.session.owner === server.loop(0) }
                owner0.forEach { onLoop(it.session.owner) { it.session.close() } }
                connect(port).use {
                    await { handler.entries.size == 7 }
                    assertSame(server.loop(0), handler.entries.last().session.owner)
                    assertEquals(listOf(1, 3), server.stats().admission!!.ownerLoads)
                }
            } finally { clients.forEach { it.close() } }
        }
    }

    @Test
    fun idleListenerWithNoClientsDoesNotReserveRejectOrSpin() = withServer { server ->
        server.start()
        idleStable(server)
        val stats = server.stats()
        assertEquals(0L, stats.acceptedClients)
        assertEquals(0, stats.admission!!.handshakes.peak)
        assertEquals(0L, stats.admission.rejectedHandshakes)
        assertEquals(0, stats.admission.pendingReservations)
    }

    @Test
    fun clientHandoffQueueSaturationClosesRejectedSocketAndReleasesLoad() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        lateinit var server: SocksNioServer
        val handler = Handler(opened = { session, _ ->
            if (session.owner === server.loop(1)) { entered.countDown(); release.await(3, TimeUnit.SECONDS) }
        })
        server = SocksNioServer(handler, config = smallConfig())
        val clients = mutableListOf<Socket>()
        try {
            val port = server.start()
            clients.add(connect(port)); await { handler.entries.size == 1 }
            clients.add(connect(port)); assertTrue(entered.await(2, TimeUnit.SECONDS))
            accepted(server.loop(1).submit {})
            clients.add(connect(port)); await { handler.entries.size == 3 }
            connect(port).use { eof(it) }
            assertEquals(1L, server.stats().rejectedTransfers)
            assertEquals(3, server.stats().admission!!.handshakes.current)
            assertEquals(listOf(2, 1), server.stats().admission!!.ownerLoads)
        } finally {
            release.countDown(); clients.forEach { it.close() }; assertTrue(server.stop()); assertClean(server)
        }
    }

    @Test
    fun clientChannelCapacityRejectionClosesClientAndReleasesReservation() {
        val handler = Handler()
        val server = SocksNioServer(handler, config = SocksEventLoopConfig(channelCapacity = 2, readinessPerTurn = 2))
        val clients = mutableListOf<Socket>()
        try {
            val port = server.start()
            repeat(2) { clients.add(connect(port)); await { handler.entries.size == it + 1 } }
            connect(port).use { eof(it) }
            assertEquals(1L, server.stats().rejectedTransfers)
            assertEquals(2, server.stats().admission!!.handshakes.current)
            assertEquals(0, server.stats().admission!!.pendingReservations)
            assertEquals(listOf(1, 1), server.stats().admission!!.ownerLoads)
        } finally { clients.forEach { it.close() }; assertTrue(server.stop()); assertClean(server) }
    }

    @Test
    fun sessionCallbackFailureClosesOnlyThatSessionAndListenerContinues() {
        val calls = AtomicInteger()
        val handler = Handler(opened = { _, _ -> if (calls.incrementAndGet() == 1) error("session callback") })
        withServer(handler) { server ->
            val port = server.start()
            connect(port).use { eof(it) }
            connect(port).use { await { calls.get() == 2 }; assertEquals(SocksNioServer.State.RUNNING, server.stats().state) }
            assertNull(server.stats().failure)
        }
    }

    @Test
    fun fatalPeerLoopFailureSupervisesWholeGroupAndClearsAdmissions() = withServer { server ->
        val port = server.start()
        connect(port).use {
            await { server.stats().admission!!.handshakes.current == 1 }
            accepted(server.loop(1).submit { throw IOException("peer failure") })
            await { server.stats().state == SocksNioServer.State.STOPPED }
            eof(it); assertClean(server)
            assertEquals("peer failure", server.stats().failure!!.message)
        }
        server.start()
        assertNull(server.stats().failure)
    }

    @Test
    fun stopFromSessionCallbackNeverWaitsForSelfOrPeer() {
        val stopped = CountDownLatch(1)
        lateinit var server: SocksNioServer
        val handler = Handler(opened = { _, _ ->
            val start = System.nanoTime()
            assertFalse(server.stop())
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 500)
            stopped.countDown()
        })
        server = SocksNioServer(handler)
        try {
            connect(server.start()).use { assertTrue(stopped.await(2, TimeUnit.SECONDS)); eof(it) }
            assertTrue(server.stop()); assertClean(server)
        } finally { server.close() }
    }

    @Test
    fun stopDuringBlockedSessionKeepsLeaseUntilOwnerCleanupAndWipesControlBuffer() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val buffer = AtomicReference<ByteBuffer>()
        val handler = Handler(opened = { session, _ ->
            buffer.set(session.allocateControlBuffer(64).also { repeat(64) { _ -> it.put(99) } })
            entered.countDown(); release.await(3, TimeUnit.SECONDS)
        })
        val server = SocksNioServer(handler)
        var client: Socket? = null
        try {
            client = connect(server.start()); assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertFalse(server.stop(100))
            assertEquals(SocksNioServer.State.STOPPING, server.stats().state)
            assertEquals(1, server.stats().admission!!.handshakes.current)
            assertEquals(1, server.stats().admission!!.ownerLoads.sum())
        } finally {
            release.countDown(); assertTrue(server.stop()); assertClean(server)
            client?.let { eof(it); it.close() }
            assertTrue(buffer.get().array().all { it == 0.toByte() })
        }
    }

    @Test
    fun realAcceptStopRaceRepeatedlyReturnsAllResourcesAndAllowsRestart() = withServer { server ->
        repeat(20) {
            val port = server.start()
            val go = CountDownLatch(1)
            val client = AtomicReference<Socket>()
            val connector = Thread {
                go.await()
                try { client.set(connect(port)) } catch (_: IOException) {}
            }
            connector.start(); go.countDown()
            assertTrue(server.stop())
            connector.join(2_000); assertFalse(connector.isAlive)
            client.get()?.let { socket ->
                try { eof(socket) } catch (error: SocketException) {
                    // Closing the listener may reset a connection still in its accept backlog.
                    assertTrue(error.message.orEmpty().contains("reset", ignoreCase = true))
                    assertEquals(0L, server.stats().acceptedClients)
                } finally { socket.close() }
            }
            assertClean(server)
            assertNull(server.stats().failure)
            server.stats().loops.forEach { loop ->
                assertEquals(0L, loop.callbackFailures)
                assertEquals(0L, loop.cleanupFailures)
                assertNull(loop.failure)
            }
        }
    }

    @Test
    fun twoConcurrentStopsShareCleanupWithoutDoubleReleases() = withServer { server ->
        repeat(10) {
            connect(server.start()).use {
                await { server.stats().admission!!.handshakes.current == 1 }
                val go = CountDownLatch(1)
                val results = ConcurrentLinkedQueue<Boolean>()
                val workers = List(2) { Thread { go.await(); results.add(server.stop()) } }
                workers.forEach { it.start() }; go.countDown()
                workers.forEach { it.join(2_000); assertFalse(it.isAlive) }
                assertEquals(listOf(true, true), results.toList()); eof(it); assertClean(server)
            }
        }
    }

    private fun connect(port: Int): Socket = Socket().apply {
        soTimeout = 2_000
        connect(loopback(port), 1_000)
    }
    private fun loopback(port: Int) = InetSocketAddress(InetAddress.getByName("127.0.0.1"), port)
    private fun eof(client: Socket) { assertEquals(-1, client.getInputStream().read()) }
    private fun accepted(result: SocksEventLoop.Submission) = assertEquals(SocksEventLoop.Submission.ACCEPTED, result)
    private fun smallConfig() = SocksEventLoopConfig(commandCapacity = 1, commandsPerTurn = 1)
    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (!condition()) { if (System.nanoTime() - deadline >= 0) fail("Condition timed out"); Thread.sleep(2) }
    }
    private fun onLoop(loop: SocksEventLoop, action: () -> Unit) {
        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable>()
        accepted(loop.submit { try { action() } catch (caught: Throwable) { error.set(caught) } finally { done.countDown() } })
        assertTrue(done.await(2, TimeUnit.SECONDS)); error.get()?.let { throw it }
    }
    private fun idleStable(server: SocksNioServer) {
        Thread.sleep(100)
        val before = server.stats().loops
        Thread.sleep(180)
        val after = server.stats().loops
        before.zip(after).forEach { (a, b) ->
            assertEquals(0L, b.selectNowCalls)
            assertTrue("idle turns ${b.turns - a.turns}", b.turns - a.turns <= 2)
            assertEquals(a.readinessCallbacks, b.readinessCallbacks)
        }
    }
    private fun assertClean(server: SocksNioServer) {
        val stats = server.stats()
        assertEquals(SocksNioServer.State.STOPPED, stats.state)
        assertNull(stats.port); assertFalse(stats.listenerRegistered)
        val admission = stats.admission!!
        assertEquals(0, admission.handshakes.current); assertEquals(0, admission.tcp.current); assertEquals(0, admission.udp.current)
        assertEquals(0, admission.pendingReservations); assertEquals(listOf(0, 0), admission.ownerLoads)
        stats.loops.forEach {
            assertEquals(SocksEventLoop.State.TERMINATED, it.state)
            assertEquals(listOf(0, 0, 0, 0, 0, 0, 0), listOf(it.commands, it.completions, it.timers, it.resources, it.channels, it.keys, it.readyKeys))
        }
    }
    private fun withServer(handler: Handler = Handler(), action: (SocksNioServer) -> Unit) {
        val server = SocksNioServer(handler)
        try { action(server) } finally { assertTrue(server.stop()); assertClean(server) }
    }
}
