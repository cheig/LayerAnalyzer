// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.Pipe
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

/** Pure JVM tests: real Selector, pipes and loopback channels; no Android, JNI or mock selector. */
class SocksEventLoopTest {
    @Test
    fun idleDefaultGroupHasTwoSleepingLoopsAndNoSelectNow() {
        val selectors = mutableListOf<Selector>()
        val group = SocksEventLoopGroup(selectorFactory = { Selector.open().also { selectors.add(it) } })
        try {
            group.start()
            assertEquals(2, group.stats().size)
            assertNotSame(group.nextLoop(), group.nextLoop())
            await { group.stats().all { it.selectCalls > 0 } }
            val before = group.stats()
            Thread.sleep(180)
            group.stats().zip(before).forEach { (after, first) ->
                assertTrue("Idle loop spinning: $after", after.turns - first.turns <= 2)
                assertEquals(0L, after.selectNowCalls)
                assertEquals(0L, after.readinessCallbacks)
            }
        } finally { assertTrue(group.shutdown()) }
        group.stats().forEach(::assertEmpty)
        assertTrue(selectors.all { !it.isOpen })
    }

    @Test
    fun idleSelectWakesForCommandCompletionAndSubmillisecondTimer() = withLoop { loop ->
        await { loop.stats().selectCalls > 0 }
        val called = CountDownLatch(3)
        assertAccepted(loop.submit { called.countDown() })
        assertAccepted(loop.complete { called.countDown() })
        assertAccepted(loop.schedule(200_000) { called.countDown() }.result)
        assertTrue(called.await(750, TimeUnit.MILLISECONDS))
        assertEquals(0L, loop.stats().selectNowCalls)
    }

    @Test
    fun saturationIsObservableAndCannotBlockStopOrCancel() {
        val loop = SocksEventLoop("saturated", smallConfig())
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val discarded = AtomicInteger()
        val executed = AtomicInteger()
        loop.start()
        try {
            loop.submit { entered.countDown(); release.await(3, TimeUnit.SECONDS) }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            repeat(2) {
                assertAccepted(loop.submit(onDiscard = { discarded.incrementAndGet() }) { executed.incrementAndGet() })
                assertAccepted(loop.complete(onDiscard = { discarded.incrementAndGet() }) { executed.incrementAndGet() })
            }
            assertEquals(SocksEventLoop.Submission.QUEUE_FULL, loop.submit(onDiscard = { fail("Caller owns rejection") }) {})
            assertEquals(SocksEventLoop.Submission.QUEUE_FULL, loop.complete {})
            val timer = loop.schedule(TimeUnit.HOURS.toNanos(1)) {}.timer!!
            assertTrue(timer.cancel())
            assertFalse(timer.retainsCallback())
            assertFalse(loop.shutdown(0))
            assertEquals(SocksEventLoop.Submission.STOPPED, loop.submit {})
            assertEquals(SocksEventLoop.Submission.STOPPED, loop.complete {})
            assertEquals(SocksEventLoop.Submission.STOPPED, loop.schedule(0) {}.result)
            assertEquals(0, discarded.get())
        } finally { release.countDown(); assertTrue(loop.shutdown()) }
        assertEquals(0, executed.get())
        assertEquals(4, discarded.get())
        assertTrue(loop.stats().rejectedCommands >= 2)
        assertTrue(loop.stats().rejectedCompletions >= 2)
        assertEmpty(loop.stats())
    }

    @Test
    fun rejectedTransferKeepsOwnershipAcceptedQueuedTransferClosesOnStop() {
        val loop = SocksEventLoop("handoff", smallConfig())
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val pipes = List(3) { Pipe.open().also { it.source().configureBlocking(false) } }
        val closed = AtomicInteger()
        loop.start()
        try {
            loop.submit { entered.countDown(); release.await(3, TimeUnit.SECONDS) }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            repeat(2) { index ->
                assertAccepted(loop.transfer(pipes[index].source(), SelectionKey.OP_READ, { _, _ -> fail("No readiness") },
                    onRegistered = { fail("Must discard") }, onClosed = { closed.incrementAndGet() }))
            }
            assertEquals(SocksEventLoop.Submission.QUEUE_FULL,
                loop.transfer(pipes[2].source(), SelectionKey.OP_READ, { _, _ -> }, onClosed = { fail("Caller owns rejection") }))
            assertTrue(pipes[2].source().isOpen)
            loop.requestStop()
            assertEquals(SocksEventLoop.Submission.STOPPED, loop.transfer(pipes[2].source(), 0, { _, _ -> }))
            assertTrue(pipes[2].source().isOpen)
        } finally {
            release.countDown()
            assertTrue(loop.shutdown())
            pipes.forEach { it.source().close(); it.sink().close() }
        }
        assertEquals(2, closed.get())
        assertEmpty(loop.stats())
    }

    @Test
    fun acceptedRegistrationFailuresCloseChannelAndNotifyOwnerThread() = withLoop { loop ->
        val pipes = List(3) { Pipe.open() }
        try {
            pipes[0].source().configureBlocking(false)
            pipes[1].source().close()
            // Invalid ops, closed channel, still blocking channel.
            val ops = listOf(SelectionKey.OP_WRITE, SelectionKey.OP_READ, SelectionKey.OP_READ)
            val closed = CountDownLatch(3)
            pipes.forEachIndexed { index, pipe ->
                assertAccepted(loop.transfer(pipe.source(), ops[index], { _, _ -> fail("No readiness") },
                    onRegistered = { fail("No registration") }, onClosed = { cause ->
                        assertTrue(loop.inEventLoop())
                        assertNotNull(cause)
                        closed.countDown()
                    }))
            }
            assertTrue(closed.await(2, TimeUnit.SECONDS))
            assertTrue(pipes.all { !it.source().isOpen })
            assertEquals(SocksEventLoop.State.RUNNING, loop.stats().state)
            await { loop.stats().channels == 0 && loop.stats().resources == 0 && loop.stats().keys == 0 }
        } finally { pipes.forEach { it.source().close(); it.sink().close() } }
    }

    @Test
    fun loopLocalRegisterFailureClosesNewChannelAndSiblingScope() = withLoop { loop ->
        val sibling = Pipe.open()
        val invalid = Pipe.open()
        try {
            sibling.source().configureBlocking(false)
            invalid.source().configureBlocking(false)
            val hooks = AtomicInteger()
            onLoop(loop) {
                val resource = loop.openResource { hooks.incrementAndGet() }
                resource.register(sibling.source(), 0) { _, _ -> }
                assertThrows(IllegalArgumentException::class.java) {
                    resource.register(invalid.source(), SelectionKey.OP_CONNECT) { _, _ -> }
                }
                assertTrue(resource.isClosed)
                assertFalse(sibling.source().isOpen)
                assertFalse(invalid.source().isOpen)
                resource.close()
            }
            assertEquals(1, hooks.get())
        } finally { listOf(sibling, invalid).forEach { it.source().close(); it.sink().close() } }
    }

    @Test
    fun closedOwnerRegisterPreconditionLeavesChannelWithCaller() = withLoop { loop ->
        val pipe = Pipe.open()
        try {
            onLoop(loop) {
                val resource = loop.openResource()
                resource.close()
                assertThrows(IllegalStateException::class.java) { resource.register(pipe.source(), 0) { _, _ -> } }
                assertTrue(pipe.source().isOpen)
            }
        } finally { pipe.source().close(); pipe.sink().close() }
    }

    @Test
    fun registrationAndInterestOpsAreLoopOnly() = withLoop { loop ->
        val pipe = Pipe.open()
        pipe.source().configureBlocking(false)
        val registration = AtomicReference<SocksEventLoop.Registration>()
        val resource = AtomicReference<SocksEventLoop.Resource>()
        try {
            onLoop(loop) {
                resource.set(loop.openResource())
                registration.set(resource.get().register(pipe.source(), 0) { _, _ -> })
            }
            assertThrows(IllegalStateException::class.java) { loop.openResource() }
            assertThrows(IllegalStateException::class.java) { registration.get().interestOps(SelectionKey.OP_READ) }
            assertThrows(IllegalStateException::class.java) { registration.get().interestOps() }
            assertThrows(IllegalStateException::class.java) { registration.get().close() }
            assertThrows(IllegalStateException::class.java) { resource.get().close() }
            onLoop(loop) { registration.get().interestOps(SelectionKey.OP_READ); resource.get().close() }
        } finally { pipe.source().close(); pipe.sink().close() }
    }

    @Test
    fun timerLimitCancelRemovesImmediatelyAndReleasesReferences() = withLoop(smallConfig()) { loop ->
        val first = loop.schedule(TimeUnit.HOURS.toNanos(1)) {}.timer!!
        val second = loop.schedule(TimeUnit.HOURS.toNanos(1)) {}.timer!!
        assertEquals(SocksEventLoop.Submission.TIMER_FULL, loop.schedule(0) {}.result)
        assertEquals(1L, loop.stats().rejectedTimers)
        assertTrue(first.cancel())
        assertFalse(first.cancel())
        assertFalse(first.retainsCallback())
        assertEquals(1, loop.stats().timers)
        val replacement = loop.schedule(TimeUnit.HOURS.toNanos(1)) {}.timer!!
        assertTrue(second.cancel())
        assertTrue(replacement.cancel())
        assertEquals(0, loop.stats().timers)
    }

    @Test
    fun timerCancelFireRaceAtMostOnceAndSuccessfulCancelPreventsCallback() = withLoop { loop ->
        repeat(100) {
            val fired = AtomicInteger()
            val timer = loop.schedule(0) { fired.incrementAndGet() }.timer!!
            val canceled = timer.cancel()
            // Command runs before timer phase, so also await claim completion when cancel loses.
            if (!canceled) await { fired.get() == 1 }
            onLoop(loop) { }
            assertTrue(fired.get() <= 1)
            if (canceled) assertEquals(0, fired.get()) else assertEquals(1, fired.get())
            assertFalse(timer.retainsCallback())
            assertFalse(timer.cancel())
        }
    }

    @Test
    fun cancelAfterFireClaimReturnsFalseWithoutDoubleFire() = withLoop { loop ->
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val count = AtomicInteger()
        val timer = loop.schedule(0) { count.incrementAndGet(); entered.countDown(); release.await(2, TimeUnit.SECONDS) }.timer!!
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertFalse(timer.cancel())
            assertFalse(timer.retainsCallback())
        } finally { release.countDown() }
        onLoop(loop) { }
        assertEquals(1, count.get())
    }

    @Test
    fun monotonicDeadlineOrderSurvivesNanoTimeWrapAndDoesNotFireEarly() {
        val now = AtomicLong(Long.MAX_VALUE - 1_000_000)
        val loop = SocksEventLoop("clock", nanoClock = now::get)
        val calls = Collections.synchronizedList(mutableListOf<Int>())
        loop.start()
        try {
            val later = loop.schedule(2_000_000) { calls.add(2) }.timer!!
            val sooner = loop.schedule(500_000) { calls.add(1) }.timer!!
            assertEquals(Long.MIN_VALUE + 999_999, later.deadlineNanos)
            onLoop(loop) { }
            assertTrue(calls.isEmpty())
            now.addAndGet(500_000)
            loop.submit { }
            await { calls.size == 1 }
            assertEquals(listOf(1), calls.toList())
            now.addAndGet(1_500_000)
            loop.submit { }
            await { calls.size == 2 }
            assertEquals(listOf(1, 2), calls.toList())
            assertFalse(sooner.cancel())
            assertThrows(IllegalArgumentException::class.java) { loop.schedule(-1) {} }
            assertThrows(IllegalArgumentException::class.java) { loop.schedule(SocksEventLoop.MAX_DELAY_NANOS + 1) {} }
        } finally { assertTrue(loop.shutdown()) }
    }

    @Test
    fun scopedCloseCancelsTimersAndDiscardsQueuedCompletion() = withLoop { loop ->
        val resource = AtomicReference<SocksEventLoop.Resource>()
        val timer = AtomicReference<SocksEventLoop.Timer>()
        val discarded = CountDownLatch(1)
        onLoop(loop) {
            resource.set(loop.openResource())
            timer.set(loop.schedule(TimeUnit.HOURS.toNanos(1), resource.get()) { fail("Closed timer") }.timer!!)
            assertAccepted(loop.complete(resource.get(), { discarded.countDown() }) { fail("Stale completion") })
            resource.get().close()
            assertEquals(0, loop.stats().timers)
            assertFalse(timer.get().retainsCallback())
        }
        assertTrue(discarded.await(2, TimeUnit.SECONDS))
        assertEquals(SocksEventLoop.Submission.OWNER_CLOSED, loop.complete(resource.get()) {})
        assertEquals(SocksEventLoop.Submission.OWNER_CLOSED, loop.schedule(0, resource.get()) {}.result)
    }

    @Test
    fun readinessFailureIsolatesSiblingChannelsAndTimerButOtherScopeContinues() = withLoop { loop ->
        val bad = Pipe.open()
        val sibling = Pipe.open()
        val good = Pipe.open()
        listOf(bad, sibling, good).forEach { it.source().configureBlocking(false) }
        val badClosed = CountDownLatch(1)
        val goodRead = CountDownLatch(1)
        val badTimer = AtomicReference<SocksEventLoop.Timer>()
        try {
            onLoop(loop) {
                val scope = loop.openResource { cause -> assertTrue(cause is IOException); badClosed.countDown() }
                scope.register(bad.source(), SelectionKey.OP_READ) { _, _ -> throw IOException("callback") }
                scope.register(sibling.source(), 0) { _, _ -> }
                badTimer.set(loop.schedule(TimeUnit.HOURS.toNanos(1), scope) {}.timer!!)
                loop.openResource().register(good.source(), SelectionKey.OP_READ) { reg, _ ->
                    (reg.channel as Pipe.SourceChannel).read(ByteBuffer.allocate(1))
                    goodRead.countDown()
                }
            }
            bad.sink().write(ByteBuffer.wrap(byteArrayOf(1)))
            good.sink().write(ByteBuffer.wrap(byteArrayOf(1)))
            assertTrue(badClosed.await(2, TimeUnit.SECONDS))
            assertTrue(goodRead.await(2, TimeUnit.SECONDS))
            assertFalse(bad.source().isOpen)
            assertFalse(sibling.source().isOpen)
            assertTrue(good.source().isOpen)
            assertFalse(badTimer.get().retainsCallback())
            assertEquals(1L, loop.stats().callbackFailures)
            assertEquals(SocksEventLoop.State.RUNNING, loop.stats().state)
        } finally { listOf(bad, sibling, good).forEach { it.source().close(); it.sink().close() } }
    }

    @Test
    fun scopedCommandAndTimerFailuresCloseOnlyTheirScope() = withLoop { loop ->
        val closed = CountDownLatch(2)
        onLoop(loop) {
            val first = loop.openResource { closed.countDown() }
            val second = loop.openResource { closed.countDown() }
            loop.complete(first) { throw IOException("completion") }
            loop.schedule(0, second) { throw IOException("timer") }
        }
        assertTrue(closed.await(2, TimeUnit.SECONDS))
        assertEquals(2L, loop.stats().callbackFailures)
        assertEquals(SocksEventLoop.State.RUNNING, loop.stats().state)
    }

    @Test
    fun unscopedFailureStopsLoopAndClosesTransferredChannel() {
        val loop = SocksEventLoop("fatal")
        val pipe = Pipe.open()
        pipe.source().configureBlocking(false)
        loop.start()
        try {
            val registered = CountDownLatch(1)
            assertAccepted(loop.transfer(pipe.source(), 0, { _, _ -> }, { registered.countDown() }))
            assertTrue(registered.await(2, TimeUnit.SECONDS))
            assertAccepted(loop.submit { throw IOException("unscoped") })
            await { loop.stats().state == SocksEventLoop.State.TERMINATED }
            assertFalse(pipe.source().isOpen)
            assertTrue(loop.stats().failure is IOException)
            assertEquals(1L, loop.stats().callbackFailures)
            assertEmpty(loop.stats())
        } finally { loop.shutdown(); pipe.source().close(); pipe.sink().close() }
    }

    @Test
    fun throwingCleanupHooksAndDiscardsDoNotLeakOrAbortCleanup() {
        val loop = SocksEventLoop("cleanup")
        val pipes = List(2) { Pipe.open().also { it.source().configureBlocking(false) } }
        loop.start()
        try {
            val registered = CountDownLatch(2)
            pipes.forEach { pipe ->
                loop.transfer(pipe.source(), 0, { _, _ -> }, { registered.countDown() }, { throw IOException("hook") })
            }
            assertTrue(registered.await(2, TimeUnit.SECONDS))
            onLoop(loop) {
                loop.submit(onDiscard = { throw IOException("discard") }) { fail("Must discard") }
                loop.requestStop()
            }
            assertTrue(loop.shutdown())
            assertTrue(pipes.all { !it.source().isOpen })
            assertEquals(3L, loop.stats().cleanupFailures)
            assertEmpty(loop.stats())
        } finally { loop.shutdown(); pipes.forEach { it.source().close(); it.sink().close() } }
    }

    @Test
    fun hotKeyCannotStarveOtherSnapshotKeysCommandsCompletionsOrTimers() = withLoop(
        SocksEventLoopConfig(commandsPerTurn = 1, completionsPerTurn = 1, timersPerTurn = 1, readinessPerTurn = 1)
    ) { loop ->
        val pipes = List(12) { Pipe.open().also { it.source().configureBlocking(false) } }
        val visits = List(12) { AtomicInteger() }
        val seen = CountDownLatch(12)
        val phases = CountDownLatch(3)
        try {
            onLoop(loop) {
                pipes.forEachIndexed { index, pipe ->
                    loop.openResource().register(pipe.source(), SelectionKey.OP_READ) { _, _ ->
                        // Deliberately unread hot pipe; no loop within the callback.
                        if (visits[index].incrementAndGet() == 1) seen.countDown()
                        if (index == 0 && visits[0].get() == 1) {
                            loop.submit { phases.countDown() }
                            loop.complete { phases.countDown() }
                            loop.schedule(0) { phases.countDown() }
                        }
                    }
                    pipe.sink().write(ByteBuffer.wrap(byteArrayOf(1)))
                }
            }
            assertTrue(seen.await(2, TimeUnit.SECONDS))
            assertTrue(phases.await(2, TimeUnit.SECONDS))
            onLoop(loop) {
                assertTrue("Unfair snapshot: ${visits.map { it.get() }}", visits.maxOf { it.get() } - visits.minOf { it.get() } <= 1)
                loop.requestStop()
            }
        } finally { loop.shutdown(); pipes.forEach { it.source().close(); it.sink().close() } }
    }

    @Test
    fun continuallyResubmittedCommandsAndDueTimersStillServiceReadiness() = withLoop(
        SocksEventLoopConfig(commandsPerTurn = 1, completionsPerTurn = 1, timersPerTurn = 1, readinessPerTurn = 1)
    ) { loop ->
        val pipe = Pipe.open()
        pipe.source().configureBlocking(false)
        val counts = List(4) { AtomicInteger() }
        val read = CountDownLatch(1)
        try {
            lateinit var command: () -> Unit
            lateinit var completion: () -> Unit
            lateinit var timer: () -> Unit
            command = { if (counts[0].incrementAndGet() < 30) loop.submit(action = command); Unit }
            completion = { if (counts[1].incrementAndGet() < 30) loop.complete(action = completion); Unit }
            timer = { if (counts[2].incrementAndGet() < 30) loop.schedule(0, action = timer); Unit }
            onLoop(loop) {
                loop.openResource().register(pipe.source(), SelectionKey.OP_READ) { _, _ -> counts[3].incrementAndGet(); read.countDown() }
                loop.submit(action = command)
                loop.complete(action = completion)
                loop.schedule(0, action = timer)
                pipe.sink().write(ByteBuffer.wrap(byteArrayOf(1)))
            }
            assertTrue(read.await(2, TimeUnit.SECONDS))
            await { counts.take(3).all { it.get() == 30 } }
        } finally { pipe.source().close(); pipe.sink().close() }
    }

    @Test
    fun writeReadinessAutoDisarmsAndIdleDoesNotSpin() = withLoop { loop ->
        ServerSocketChannel.open().use { server ->
            server.bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
            SocketChannel.open(server.localAddress).use { client ->
                server.accept().use { peer ->
                    client.configureBlocking(false)
                    val written = CountDownLatch(1)
                    val registration = AtomicReference<SocksEventLoop.Registration>()
                    assertAccepted(loop.transfer(client, SelectionKey.OP_WRITE, { reg, ops ->
                        assertEquals(SelectionKey.OP_WRITE, ops)
                        assertEquals(0, reg.interestOps() and SelectionKey.OP_WRITE)
                        written.countDown()
                    }, { registration.set(it) }))
                    assertTrue(written.await(2, TimeUnit.SECONDS))
                    onLoop(loop) { }
                    val before = loop.stats()
                    Thread.sleep(120)
                    assertEquals(before.readinessCallbacks, loop.stats().readinessCallbacks)
                    assertTrue(loop.stats().turns - before.turns <= 2)
                    onLoop(loop) { registration.get().pendingWrite(true) }
                    await { loop.stats().readinessCallbacks == 2L }
                    onLoop(loop) { registration.get().pendingWrite(false); registration.get().resource.close() }
                    assertFalse(client.isOpen)
                    assertTrue(peer.isOpen)
                }
            }
        }
    }

    @Test
    fun submitStopRaceAccountsEveryAcceptedPayloadExactlyOnce() {
        repeat(20) {
            val loop = SocksEventLoop("race-$it")
            loop.start()
            val start = CountDownLatch(1)
            val submittedFirst = CountDownLatch(1)
            val accepted = AtomicInteger()
            val accounted = AtomicInteger()
            val producer = Thread {
                start.await()
                repeat(200) {
                    if (loop.submit(onDiscard = { accounted.incrementAndGet() }) { accounted.incrementAndGet() } ==
                        SocksEventLoop.Submission.ACCEPTED) accepted.incrementAndGet()
                    submittedFirst.countDown()
                }
            }
            producer.start()
            start.countDown()
            assertTrue(submittedFirst.await(2, TimeUnit.SECONDS))
            loop.requestStop()
            producer.join(2_000)
            assertFalse(producer.isAlive)
            assertTrue(loop.shutdown())
            assertEquals(accepted.get(), accounted.get())
            assertEmpty(loop.stats())
        }
    }

    @Test
    fun transferStopRaceClosesOnlyAcceptedChannelsExactlyOnce() {
        repeat(20) {
            val loop = SocksEventLoop("transfer-race-$it")
            val pipe = Pipe.open()
            pipe.source().configureBlocking(false)
            val start = CountDownLatch(1)
            val result = AtomicReference<SocksEventLoop.Submission>()
            val hooks = AtomicInteger()
            loop.start()
            val producer = Thread {
                start.await()
                result.set(loop.transfer(pipe.source(), SelectionKey.OP_READ, { _, _ -> }, onClosed = { hooks.incrementAndGet() }))
            }
            try {
                producer.start()
                start.countDown()
                loop.requestStop()
                producer.join(2_000)
                assertFalse(producer.isAlive)
                assertTrue(loop.shutdown())
                if (result.get() == SocksEventLoop.Submission.ACCEPTED) {
                    assertFalse(pipe.source().isOpen)
                    assertEquals(1, hooks.get())
                } else {
                    assertTrue(pipe.source().isOpen)
                    assertEquals(0, hooks.get())
                }
                assertEmpty(loop.stats())
            } finally { loop.shutdown(); pipe.source().close(); pipe.sink().close() }
        }
    }

    @Test
    fun groupShutdownUsesOneDeadlineAndReportsUncooperativeCallbacks() {
        val group = SocksEventLoopGroup()
        val entered = CountDownLatch(2)
        val release = CountDownLatch(1)
        group.start()
        try {
            repeat(2) { group.loop(it).submit { entered.countDown(); release.await(3, TimeUnit.SECONDS) } }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            val before = System.nanoTime()
            assertFalse(group.shutdown(120))
            val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - before)
            assertTrue("Timeout multiplied: $elapsed ms", elapsed < 220)
            group.stats().forEach { assertEquals(SocksEventLoop.State.STOPPING, it.state) }
        } finally { release.countDown(); assertTrue(group.shutdown()) }
        group.stats().forEach(::assertEmpty)
    }

    @Test
    fun groupShutdownFromLoopNeverWaitsForSelfOrPeer() {
        val group = SocksEventLoopGroup()
        val peerEntered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val stopped = CountDownLatch(1)
        group.start()
        try {
            group.loop(1).submit { peerEntered.countDown(); release.await(3, TimeUnit.SECONDS) }
            assertTrue(peerEntered.await(2, TimeUnit.SECONDS))
            group.loop(0).submit { assertFalse(group.shutdown()); stopped.countDown() }
            assertTrue(stopped.await(500, TimeUnit.MILLISECONDS))
        } finally { release.countDown(); assertTrue(group.shutdown()) }
        group.stats().forEach(::assertEmpty)
    }

    @Test
    fun neverStartedRepeatedCloseRejectsWithoutOpeningSelectorOrTakingChannel() {
        val opened = AtomicInteger()
        val group = SocksEventLoopGroup(selectorFactory = { opened.incrementAndGet(); Selector.open() })
        val pipe = Pipe.open()
        try {
            assertEquals(SocksEventLoop.Submission.NOT_STARTED, group.loop(0).submit {})
            assertEquals(SocksEventLoop.Submission.NOT_STARTED, group.loop(0).schedule(0) {}.result)
            assertEquals(SocksEventLoop.Submission.NOT_STARTED, group.loop(0).transfer(pipe.source(), 0, { _, _ -> }))
            assertTrue(group.shutdown())
            assertTrue(group.shutdown())
            assertEquals(SocksEventLoop.Submission.STOPPED, group.loop(0).submit {})
            assertThrows(IllegalStateException::class.java) { group.start() }
            assertEquals(0, opened.get())
            assertTrue(pipe.source().isOpen)
            group.stats().forEach(::assertEmpty)
        } finally { pipe.source().close(); pipe.sink().close() }
    }

    @Test
    fun secondSelectorStartFailureClosesFirstAndUnstartedLoop() {
        val first = AtomicReference<Selector>()
        val group = SocksEventLoopGroup(selectorFactory = { index ->
            if (index == 1) throw IOException("second selector")
            Selector.open().also { first.set(it) }
        })
        assertThrows(IOException::class.java) { group.start() }
        assertTrue(group.shutdown())
        assertFalse(first.get().isOpen)
        group.stats().forEach(::assertEmpty)
    }

    @Test
    fun firstSelectorStartFailureLeavesNoThreadsOrSelectors() {
        val group = SocksEventLoopGroup(selectorFactory = { throw IOException("first selector") })
        assertThrows(IOException::class.java) { group.start() }
        assertTrue(group.shutdown())
        group.stats().forEach(::assertEmpty)
    }

    @Test
    fun secondThreadStartFailureClosesBothOpenedSelectors() {
        val opened = mutableListOf<Selector>()
        val group = SocksEventLoopGroup(selectorFactory = { Selector.open().also { opened.add(it) } },
            threadFactory = { task, name ->
                if (name.endsWith("1")) object : Thread(task, name) {
                    override fun start() { throw IllegalStateException("thread start injected failure") }
                } else Thread(task, name)
            })
        assertThrows(IllegalStateException::class.java) { group.start() }
        assertTrue(group.shutdown())
        assertEquals(2, opened.size)
        assertTrue(opened.all { !it.isOpen })
        group.stats().forEach(::assertEmpty)
    }

    @Test
    fun closeDuringSecondSelectorFactoryHasBoundedWaitAndCleansLateSelector() {
        val opened = Collections.synchronizedList(mutableListOf<Selector>())
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val group = SocksEventLoopGroup(selectorFactory = { index ->
            if (index == 1) { entered.countDown(); release.await(3, TimeUnit.SECONDS) }
            Selector.open().also { opened.add(it) }
        })
        val startFailure = AtomicReference<Throwable>()
        val starter = Thread { try { group.start() } catch (error: Throwable) { startFailure.set(error) } }
        starter.start()
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            val before = System.nanoTime()
            assertFalse(group.shutdown(50))
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - before) < 200)
            assertEquals(SocksEventLoop.Submission.STOPPED, group.loop(1).submit {})
        } finally { release.countDown() }
        starter.join(2_000)
        assertFalse(starter.isAlive)
        assertNotNull(startFailure.get())
        assertTrue(group.shutdown())
        assertTrue(opened.all { !it.isOpen })
        group.stats().forEach(::assertEmpty)
    }

    @Test
    fun channelAndResourceLimitsBoundOwnership() = withLoop(
        smallConfig().copy(channelCapacity = 1, resourceCapacity = 1, readinessPerTurn = 1)
    ) { loop ->
        val first = Pipe.open()
        val rejected = Pipe.open()
        listOf(first, rejected).forEach { it.source().configureBlocking(false) }
        try {
            val registered = CountDownLatch(1)
            assertAccepted(loop.transfer(first.source(), 0, { _, _ -> }, { registered.countDown() }))
            assertTrue(registered.await(2, TimeUnit.SECONDS))
            assertEquals(SocksEventLoop.Submission.CHANNEL_LIMIT, loop.transfer(rejected.source(), 0, { _, _ -> }))
            assertTrue(rejected.source().isOpen)
            onLoop(loop) { assertThrows(IllegalStateException::class.java) { loop.openResource() } }
        } finally { loop.shutdown(); listOf(first, rejected).forEach { it.source().close(); it.sink().close() } }
    }

    @Test
    fun foreignScopeIsRejectedWithoutTransferringWork() {
        val group = SocksEventLoopGroup()
        val owner = AtomicReference<SocksEventLoop.Resource>()
        group.start()
        try {
            onLoop(group.loop(0)) { owner.set(group.loop(0).openResource()) }
            assertThrows(IllegalArgumentException::class.java) { group.loop(1).submit(owner.get()) {} }
            assertThrows(IllegalArgumentException::class.java) { group.loop(1).complete(owner.get()) {} }
            assertThrows(IllegalArgumentException::class.java) { group.loop(1).schedule(0, owner.get()) {} }
        } finally { assertTrue(group.shutdown()) }
    }

    @Test
    fun oneUnreadHotKeyDoesNotStarveColdKeysOrTimer() = withLoop(
        SocksEventLoopConfig(readinessPerTurn = 1, timersPerTurn = 1)
    ) { loop ->
        val pipes = List(10) { Pipe.open().also { it.source().configureBlocking(false) } }
        val coldReads = CountDownLatch(9)
        val timerFired = CountDownLatch(1)
        val hotVisits = AtomicInteger()
        try {
            onLoop(loop) {
                pipes.forEachIndexed { index, pipe ->
                    loop.openResource().register(pipe.source(), SelectionKey.OP_READ) { reg, _ ->
                        if (index == 0) hotVisits.incrementAndGet()
                        else {
                            (reg.channel as Pipe.SourceChannel).read(ByteBuffer.allocate(1))
                            coldReads.countDown()
                            reg.resource.close()
                        }
                    }
                    pipe.sink().write(ByteBuffer.wrap(byteArrayOf(1)))
                }
                loop.schedule(TimeUnit.MILLISECONDS.toNanos(5)) { timerFired.countDown() }
            }
            assertTrue(coldReads.await(2, TimeUnit.SECONDS))
            assertTrue(timerFired.await(2, TimeUnit.SECONDS))
            assertTrue(hotVisits.get() > 0)
        } finally { loop.shutdown(); pipes.forEach { it.source().close(); it.sink().close() } }
    }

    @Test
    fun timerFireCancelStopRaceClearsAllPendingCallbacks() {
        repeat(20) {
            val loop = SocksEventLoop("timer-stop-$it")
            loop.start()
            val fired = AtomicInteger()
            val timer = loop.schedule(0) { fired.incrementAndGet() }.timer!!
            val canceled = timer.cancel()
            loop.requestStop()
            assertTrue(loop.shutdown())
            assertTrue(fired.get() <= 1)
            if (canceled) assertEquals(0, fired.get())
            assertFalse(timer.retainsCallback())
            assertEmpty(loop.stats())
        }
    }

    @Test
    fun interruptedLoopStopsRatherThanSpinningOnSelect() {
        val worker = AtomicReference<Thread>()
        val loop = SocksEventLoop("interrupt", threadFactory = { task, name -> Thread(task, name).also { worker.set(it) } })
        val pipe = Pipe.open()
        pipe.source().configureBlocking(false)
        loop.start()
        try {
            onLoop(loop) { loop.openResource().register(pipe.source(), 0) { _, _ -> } }
            worker.get().interrupt()
            await { loop.stats().state == SocksEventLoop.State.TERMINATED }
            assertFalse(pipe.source().isOpen)
            assertEmpty(loop.stats())
        } finally { loop.shutdown(); pipe.source().close(); pipe.sink().close() }
    }

    @Test
    fun registerCallbackFailureClosesChannelAndNotifiesExactlyOnce() = withLoop { loop ->
        val pipe = Pipe.open()
        pipe.source().configureBlocking(false)
        val closed = CountDownLatch(1)
        val hooks = AtomicInteger()
        try {
            assertAccepted(loop.transfer(pipe.source(), 0, { _, _ -> },
                { throw IOException("registered callback") }, { cause ->
                    assertTrue(cause is IOException)
                    hooks.incrementAndGet()
                    closed.countDown()
                }))
            assertTrue(closed.await(2, TimeUnit.SECONDS))
            assertFalse(pipe.source().isOpen)
            assertEquals(1, hooks.get())
            assertEquals(1L, loop.stats().callbackFailures)
            assertEquals(SocksEventLoop.State.RUNNING, loop.stats().state)
        } finally { pipe.source().close(); pipe.sink().close() }
    }

    @Test
    fun unscopedTimerFailureHasExplicitStopPolicy() {
        val loop = SocksEventLoop("fatal-timer")
        loop.start()
        loop.schedule(0) { throw IOException("timer without scope") }
        await { loop.stats().state == SocksEventLoop.State.TERMINATED }
        assertTrue(loop.shutdown())
        assertTrue(loop.stats().failure is IOException)
        assertEmpty(loop.stats())
    }
    @Test
    fun partialGroupStartFailureCleansFirstLoopsRealTransferredResources() {
        val pipe = Pipe.open()
        pipe.source().configureBlocking(false)
        val registered = CountDownLatch(1)
        val closed = CountDownLatch(1)
        val timer = AtomicReference<SocksEventLoop.Timer>()
        lateinit var group: SocksEventLoopGroup
        group = SocksEventLoopGroup(selectorFactory = { index ->
            if (index == 0) Selector.open() else {
                assertAccepted(group.loop(0).transfer(pipe.source(), SelectionKey.OP_READ, { _, _ -> },
                    { reg ->
                        timer.set(group.loop(0).schedule(TimeUnit.HOURS.toNanos(1), reg.resource) {}.timer!!)
                        registered.countDown()
                    }, { closed.countDown() }))
                assertTrue(registered.await(2, TimeUnit.SECONDS))
                throw IOException("second selector after first resource handoff")
            }
        })
        try {
            assertThrows(IOException::class.java) { group.start() }
            assertTrue(group.shutdown())
            assertTrue(closed.await(500, TimeUnit.MILLISECONDS))
            assertFalse(pipe.source().isOpen)
            assertFalse(timer.get().retainsCallback())
            group.stats().forEach(::assertEmpty)
        } finally { group.shutdown(); pipe.source().close(); pipe.sink().close() }
    }

    @Test
    fun acceptedTransferClosesWhenScopeCapacityExhausted() = withLoop(
        SocksEventLoopConfig(resourceCapacity = 1)
    ) { loop ->
        val pipe = Pipe.open()
        pipe.source().configureBlocking(false)
        val closed = CountDownLatch(1)
        try {
            onLoop(loop) { loop.openResource() }
            assertAccepted(loop.transfer(pipe.source(), 0, { _, _ -> }, { fail("No scope capacity") }, { cause ->
                assertTrue(cause is IllegalStateException)
                closed.countDown()
            }))
            assertTrue(closed.await(2, TimeUnit.SECONDS))
            assertFalse(pipe.source().isOpen)
            assertEquals(1, loop.stats().resources)
            assertEquals(0, loop.stats().channels)
            assertEquals(SocksEventLoop.State.RUNNING, loop.stats().state)
        } finally { pipe.source().close(); pipe.sink().close() }
    }

    @Test
    fun loopLocalCapacityFailureClosesNewChannelAndResource() = withLoop(
        SocksEventLoopConfig(channelCapacity = 1, readinessPerTurn = 1)
    ) { loop ->
        val pipes = List(2) { Pipe.open().also { it.source().configureBlocking(false) } }
        try {
            onLoop(loop) {
                val resource = loop.openResource()
                resource.register(pipes[0].source(), 0) { _, _ -> }
                assertThrows(IllegalStateException::class.java) { resource.register(pipes[1].source(), 0) { _, _ -> } }
                assertTrue(resource.isClosed)
                assertTrue(pipes.all { !it.source().isOpen })
                assertEquals(0, loop.stats().channels)
            }
        } finally { pipes.forEach { it.source().close(); it.sink().close() } }
    }
    private fun smallConfig() = SocksEventLoopConfig(
        commandCapacity = 2, completionCapacity = 2, timerCapacity = 2,
        commandsPerTurn = 1, completionsPerTurn = 1, timersPerTurn = 1
    )

    private fun withLoop(config: SocksEventLoopConfig = SocksEventLoopConfig(), action: (SocksEventLoop) -> Unit) {
        val loop = SocksEventLoop("test-loop", config)
        loop.start()
        try { action(loop) } finally { assertTrue(loop.shutdown()); assertEmpty(loop.stats()) }
    }

    private fun onLoop(loop: SocksEventLoop, action: () -> Unit) {
        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable>()
        assertAccepted(loop.submit {
            try { action() } catch (failure: Throwable) { error.set(failure) } finally { done.countDown() }
        })
        assertTrue("Owner callback did not finish: ${loop.stats()}", done.await(2, TimeUnit.SECONDS))
        error.get()?.let { throw AssertionError("Owner assertion failed", it) }
    }

    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (!condition()) {
            if (System.nanoTime() - deadline >= 0) fail("Timed out waiting for condition")
            Thread.sleep(2)
        }
    }

    private fun assertAccepted(result: SocksEventLoop.Submission) = assertEquals(SocksEventLoop.Submission.ACCEPTED, result)

    private fun assertEmpty(stats: SocksEventLoop.Stats) {
        assertEquals(stats.toString(), SocksEventLoop.State.TERMINATED, stats.state)
        assertEquals(0, stats.commands)
        assertEquals(0, stats.completions)
        assertEquals(0, stats.timers)
        assertEquals(0, stats.resources)
        assertEquals(0, stats.channels)
        assertEquals(0, stats.keys)
        assertEquals(0, stats.readyKeys)
        assertEquals(0L, stats.selectNowCalls)
    }
}
