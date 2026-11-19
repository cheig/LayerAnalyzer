// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksSessionBudget
import com.example.layanalyzer.capture.SocksSessionLimits
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

class SocksSessionTest {
    private val tcp = SocksSessionAdmission.Protocol.TCP
    private val udp = SocksSessionAdmission.Protocol.UDP

    @Test
    fun legacyBudgetAndIdempotentConcurrentLeasesKeepStats() {
        val budget = SocksSessionBudget(2)
        assertTrue(budget.tryAcquire())
        val lease = budget.tryAcquireLease()!!
        assertNull(budget.tryAcquireLease())
        assertEquals(2, budget.snapshot().peak)
        val start = CountDownLatch(1)
        val workers = List(8) { Thread { start.await(); repeat(100) { lease.close() } } }
        workers.forEach { it.start() }; start.countDown(); workers.forEach { it.join(2_000); assertFalse(it.isAlive) }
        assertTrue(lease.isReleased)
        assertEquals(1, budget.snapshot().current)
        budget.release()
        assertEquals(0, budget.snapshot().current)
        assertThrows(IllegalStateException::class.java) { budget.release() }
    }

    @Test
    fun limitsMayShrinkButNeitherProtocolNorHandshakeMayExpand() {
        listOf(SocksSessionLimits(), SocksSessionLimits(handshakes = 1, tcp = 2, udp = 3)).forEach { limits ->
            withGroup(limits = limits) { group ->
                val stats = group.sessionAdmission.stats()
                assertEquals(limits.handshakes, stats.handshakes.limit)
                assertEquals(limits.tcp, stats.tcp.limit)
                assertEquals(limits.udp, stats.udp.limit)
            }
        }
        assertThrows(IllegalArgumentException::class.java) { SocksSessionLimits(handshakes = 65) }
        assertThrows(IllegalArgumentException::class.java) { SocksSessionLimits(tcp = 65) }
        assertThrows(IllegalArgumentException::class.java) { SocksSessionLimits(udp = 65) }
    }

    @Test
    fun twoLoopsShareExactly64HandshakeAdmissionsUnderConcurrentIngress() = withGroup { group ->
        val reservations = Collections.synchronizedList(mutableListOf<SocksSessionAdmission.Reservation>())
        val start = CountDownLatch(1)
        val workers = List(2) { index -> Thread {
            start.await()
            repeat(64) { group.sessionAdmission.reserve(7, group.loop(index))?.let { reservations.add(it) } }
        } }
        workers.forEach { it.start() }; start.countDown(); workers.forEach { it.join(2_000); assertFalse(it.isAlive) }
        assertEquals(64, reservations.size)
        val stats = group.sessionAdmission.stats()
        assertEquals(64, stats.handshakes.current)
        assertEquals(64, stats.handshakes.peak)
        assertEquals(64L, stats.rejectedHandshakes)
        assertEquals(64, stats.pendingReservations)
        reservations.forEach { it.close(); it.close() }
        assertZero(group)
    }

    @Test
    fun realSessionsOnBothLoopsShare64TcpAnd64UdpWithNoCrossProtocolStarvation() = withGroup { group ->
        val opened = mutableListOf<Opened>()
        try {
            listOf(tcp, udp).forEach { protocol ->
                repeat(64) { index ->
                    val session = open(group, index % 2)
                    opened.add(session)
                    onLoop(session.session.owner) { request(session.session); assertTrue(session.session.admitProtocol(protocol)) }
                }
                val denied = open(group, 1)
                opened.add(denied)
                onLoop(denied.session.owner) {
                    request(denied.session)
                    assertFalse(denied.session.admitProtocol(protocol))
                    assertTrue(denied.session.snapshot().hasHandshakeLease)
                    denied.session.close()
                }
            }
            val stats = group.sessionAdmission.stats()
            assertEquals(64, stats.tcp.current)
            assertEquals(64, stats.udp.current)
            assertEquals(64, stats.tcp.peak)
            assertEquals(64, stats.udp.peak)
            assertEquals(0, stats.handshakes.current)
            assertEquals(0, stats.pendingReservations)
            assertEquals(1L, stats.rejectedTcp)
            assertEquals(1L, stats.rejectedUdp)
            opened.forEach { onLoop(it.session.owner) { it.session.close() } }
            assertZero(group)
        } finally { opened.forEach { it.pipe.sink().close() } }
    }

    @Test
    fun simultaneousPromotionsAcrossTwoLoopsDoNotOverAdmitOrDoubleRelease() = withGroup(
        limits = SocksSessionLimits(handshakes = 8, tcp = 3, udp = 2)
    ) { group ->
        val opened = List(8) { open(group, it % 2) }
        val done = CountDownLatch(2)
        try {
            repeat(2) { index -> accepted(group.loop(index).submit {
                try {
                    opened.filter { it.session.owner === group.loop(index) }.forEach {
                        request(it.session); it.session.admitProtocol(tcp)
                    }
                } finally { done.countDown() }
            }) }
            assertTrue(done.await(2, TimeUnit.SECONDS))
            assertEquals(3, group.sessionAdmission.stats().tcp.current)
            assertEquals(5, group.sessionAdmission.stats().handshakes.current)
            assertEquals(5L, group.sessionAdmission.stats().rejectedTcp)
            opened.forEach { onLoop(it.session.owner) { it.session.close(); it.session.close() } }
            assertZero(group)
        } finally { opened.forEach { it.pipe.sink().close() } }
    }

    @Test
    fun fullProtocolTransferRetainsHandshakeUntilExplicitCloseAndCanRetry() = withGroup(
        limits = SocksSessionLimits(handshakes = 2, tcp = 1, udp = 1)
    ) { group ->
        val first = open(group, 0)
        val second = open(group, 1)
        try {
            onLoop(first.session.owner) { request(first.session); assertTrue(first.session.admitProtocol(tcp)) }
            onLoop(second.session.owner) {
                request(second.session)
                assertFalse(second.session.admitProtocol(tcp))
                val snapshot = second.session.snapshot()
                assertEquals(SocksSession.State.REQUEST, snapshot.state)
                assertTrue(snapshot.hasHandshakeLease)
                assertFalse(snapshot.hasProtocolLease)
            }
            assertEquals(1, group.sessionAdmission.stats().handshakes.current)
            onLoop(first.session.owner) { first.session.close() }
            onLoop(second.session.owner) {
                assertTrue(second.session.admitProtocol(tcp))
                assertFalse(second.session.snapshot().hasHandshakeLease)
                assertTrue(second.session.snapshot().hasProtocolLease)
                assertThrows(IllegalStateException::class.java) { second.session.admitProtocol(udp) }
                second.session.close()
            }
            assertZero(group)
        } finally { first.pipe.sink().close(); second.pipe.sink().close() }
    }

    @Test
    fun reservationCloseAfterHandoffCannotReleaseLiveSessionOrRepeatTransfer() = withGroup { group ->
        val reservation = group.sessionAdmission.reserve(9, group.loop(1))!!
        val opened = transfer(reservation)
        val extra = pipe()
        try {
            reservation.close(); reservation.close()
            assertEquals(1, group.sessionAdmission.stats().handshakes.current)
            assertEquals(0, group.sessionAdmission.stats().pendingReservations)
            assertThrows(IllegalStateException::class.java) {
                reservation.transfer(extra.source(), 0, { _, _, _ -> }, { _, _ -> })
            }
            assertTrue(extra.source().isOpen)
            onLoop(opened.session.owner) { opened.session.close() }
            assertZero(group)
        } finally { opened.pipe.sink().close(); extra.source().close(); extra.sink().close() }
    }

    @Test
    fun queueFullHandoffReleasesReservationButCallerRetainsChannel() = withGroup(config = smallConfig()) { group ->
        val owner = group.loop(0)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val reservation = group.sessionAdmission.reserve(1, owner)!!
        val channel = pipe()
        try {
            accepted(owner.submit { entered.countDown(); release.await(3, TimeUnit.SECONDS) })
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            repeat(2) { accepted(owner.submit {}) }
            assertEquals(SocksEventLoop.Submission.QUEUE_FULL,
                reservation.transfer(channel.source(), 0, { _, _, _ -> fail() }, { _, _ -> fail() }, { fail() }))
            assertTrue(channel.source().isOpen)
            reservation.close()
            assertZero(group)
        } finally { release.countDown(); channel.source().close(); channel.sink().close() }
    }

    @Test
    fun channelCapacityRejectionConsumesLeaseButNotChannel() = withGroup(
        config = SocksEventLoopConfig(channelCapacity = 1, readinessPerTurn = 1)
    ) { group ->
        val first = open(group, 0)
        val reservation = group.sessionAdmission.reserve(1, group.loop(0))!!
        val rejected = pipe()
        try {
            assertEquals(SocksEventLoop.Submission.CHANNEL_LIMIT,
                reservation.transfer(rejected.source(), 0, { _, _, _ -> }, { _, _ -> }))
            assertTrue(rejected.source().isOpen)
            assertEquals(1, group.sessionAdmission.stats().handshakes.current)
            onLoop(first.session.owner) { first.session.close() }
            assertZero(group)
        } finally { first.pipe.sink().close(); rejected.source().close(); rejected.sink().close() }
    }

    @Test
    fun invalidBlockingClosedAndScopeExhaustedRegistrationReleaseOnOwner() {
        val configurations = listOf(SocksEventLoopConfig(), SocksEventLoopConfig(resourceCapacity = 1))
        configurations.forEach { config -> withGroup(config = config) { group ->
            if (config.resourceCapacity == 1) onLoop(group.loop(0)) { group.loop(0).openResource() }
            repeat(if (config.resourceCapacity == 1) 1 else 3) { index ->
                val channel = Pipe.open()
                if (index != 1) channel.source().configureBlocking(false)
                if (index == 2) channel.source().close()
                val closed = CountDownLatch(1)
                val error = AtomicReference<Throwable>()
                try {
                    val reservation = group.sessionAdmission.reserve(1, group.loop(0))!!
                    accepted(reservation.transfer(channel.source(),
                        if (index == 0 && config.resourceCapacity != 1) SelectionKey.OP_WRITE else 0,
                        { _, _, _ -> fail() }, { _, _ -> fail("Must not create session") }, { cause ->
                            if (!group.loop(0).inEventLoop() || cause == null) error.set(AssertionError("Missing owner/cause"))
                            closed.countDown()
                        }))
                    assertTrue(closed.await(2, TimeUnit.SECONDS))
                    error.get()?.let { throw it }
                    assertFalse(channel.source().isOpen)
                    assertZero(group)
                } finally { channel.source().close(); channel.sink().close() }
            }
        } }
    }

    @Test
    fun queuedAcceptedHandoffOnStopClosesChannelAndLeaseWithoutSession() = withGroup { group ->
        val owner = group.loop(0)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val channel = pipe()
        val closed = CountDownLatch(1)
        try {
            accepted(owner.submit { entered.countDown(); release.await(3, TimeUnit.SECONDS) })
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            val reservation = group.sessionAdmission.reserve(1, owner)!!
            accepted(reservation.transfer(channel.source(), 0, { _, _, _ -> fail() }, { _, _ -> fail() }, {
                assertTrue(owner.inEventLoop()); closed.countDown()
            }))
            group.requestStop()
            // Lease is owner-held until discard, not revoked by reservation.close or group admission.
            reservation.close()
            assertEquals(1, group.sessionAdmission.stats().handshakes.current)
            release.countDown()
            assertTrue(group.shutdown())
            assertTrue(closed.await(1, TimeUnit.SECONDS))
            assertFalse(channel.source().isOpen)
            assertZero(group)
        } finally { release.countDown(); channel.source().close(); channel.sink().close() }
    }

    @Test
    fun stopRevokesOnlyUntransferredReservationsAndRejectionLeavesChannelWithCaller() = withGroup { group ->
        val reservation = group.sessionAdmission.reserve(1)!!
        val channel = pipe()
        try {
            group.requestStop()
            assertZero(group)
            assertNull(group.sessionAdmission.reserve(1))
            assertEquals(SocksEventLoop.Submission.STOPPED,
                reservation.transfer(channel.source(), 0, { _, _, _ -> fail() }, { _, _ -> fail() }))
            assertTrue(channel.source().isOpen)
            reservation.close(); assertZero(group)
        } finally { channel.source().close(); channel.sink().close() }
    }

    @Test
    fun authRequestDeadlineDoesNotResetAndQueuedExpiredSessionNeverEscapesFactory() = withGroup { group ->
        val owner = group.loop(0)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val channel = pipe()
        val closed = CountDownLatch(1)
        val cause = AtomicReference<Throwable>()
        try {
            accepted(owner.submit { entered.countDown(); release.await(3, TimeUnit.SECONDS) })
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            val reservation = group.sessionAdmission.reserve(1, owner, TimeUnit.MILLISECONDS.toNanos(30))!!
            accepted(reservation.transfer(channel.source(), 0, { _, _, _ -> fail() }, { _, _ -> fail() }, {
                cause.set(it); closed.countDown()
            }))
            Thread.sleep(60)
            release.countDown()
            assertTrue(closed.await(2, TimeUnit.SECONDS))
            assertTrue(cause.get() is SocksSession.DeadlineExceededException)
            assertFalse(channel.source().isOpen)
            assertZero(group)
        } finally { release.countDown(); channel.source().close(); channel.sink().close() }
        val opened = open(group, 1)
        try {
            onLoop(opened.session.owner) {
                val deadline = opened.session.snapshot().deadlineNanos
                assertTrue(opened.session.enterAuth())
                assertEquals(deadline, opened.session.snapshot().deadlineNanos)
                assertTrue(opened.session.enterRequest())
                assertEquals(deadline, opened.session.snapshot().deadlineNanos)
                opened.session.close()
            }
        } finally { opened.pipe.sink().close() }
    }

    @Test
    fun handshakeTimeoutClosesRealChannelAndAllStorage() = withGroup { group ->
        val closed = CountDownLatch(1)
        val opened = transfer(group.sessionAdmission.reserve(1, group.loop(0), TimeUnit.MILLISECONDS.toNanos(300))!!,
            onSession = { session, _ -> session.allocateControlBuffer(16).put(ByteArray(16) { 55 }) },
            onClosed = { closed.countDown() })
        try {
            assertTrue(closed.await(2, TimeUnit.SECONDS))
            assertFalse(opened.pipe.source().isOpen)
            onLoop(opened.session.owner) { assertCleared(opened.session); assertTrue(opened.session.snapshot().closeCause is SocksSession.DeadlineExceededException) }
            assertZero(group)
            await { group.loop(0).stats().timers == 0 && group.loop(0).stats().keys == 0 }
        } finally { opened.pipe.sink().close() }
    }

    @Test
    fun failureReplyStillHoldsHandshakeAndCannotExtendHandshakeDeadline() = withGroup { group ->
        val opened = open(group, 0)
        try {
            onLoop(opened.session.owner) {
                request(opened.session)
                val before = opened.session.snapshot().deadlineNanos!!
                assertTrue(opened.session.enterFailing(TimeUnit.MINUTES.toNanos(1)))
                assertEquals(before, opened.session.snapshot().deadlineNanos)
                assertEquals(SocksSession.State.FAILING, opened.session.snapshot().state)
                assertTrue(opened.session.snapshot().hasHandshakeLease)
                opened.session.close()
            }
            assertZero(group)
        } finally { opened.pipe.sink().close() }
    }

    @Test
    fun timerCapacityFailureAtFactoryClosesScopeChannelAndLease() = withGroup(
        config = SocksEventLoopConfig(timerCapacity = 1, timersPerTurn = 1)
    ) { group ->
        val owner = group.loop(0)
        val existing = owner.schedule(TimeUnit.HOURS.toNanos(1)) {}.timer!!
        val channel = pipe()
        val closed = CountDownLatch(1)
        val cause = AtomicReference<Throwable>()
        try {
            accepted(group.sessionAdmission.reserve(1, owner)!!.transfer(channel.source(), 0,
                { _, _, _ -> fail() }, { _, _ -> fail() }, { cause.set(it); closed.countDown() }))
            assertTrue(closed.await(2, TimeUnit.SECONDS))
            assertTrue(cause.get() is SocksSession.SchedulingRejectedException)
            assertFalse(channel.source().isOpen)
            assertZero(group)
        } finally { existing.cancel(); channel.source().close(); channel.sink().close() }
    }

    @Test
    fun operationTimerRejectionClosesSessionAndReleasesProtocolLease() = withGroup(
        config = SocksEventLoopConfig(timerCapacity = 1, timersPerTurn = 1)
    ) { group ->
        val opened = open(group, 0)
        try {
            onLoop(opened.session.owner) {
                request(opened.session); assertTrue(opened.session.admitProtocol(tcp))
                val unscoped = opened.session.owner.schedule(TimeUnit.HOURS.toNanos(1)) {}.timer!!
                try {
                    assertNull(opened.session.beginOperation(TimeUnit.SECONDS.toNanos(1)))
                    assertCleared(opened.session)
                } finally { unscoped.cancel() }
            }
            assertZero(group)
        } finally { opened.pipe.sink().close() }
    }

    @Test
    fun completionRejectsWrongGenerationSessionOperationAndReplacedOperation() = withGroup { group ->
        val opened = open(group, 0)
        val discarded = AtomicInteger()
        val executed = AtomicInteger()
        val token = AtomicReference<SocksSession.Operation>()
        val previous = AtomicReference<SocksSession.Operation>()
        try {
            onLoop(opened.session.owner) {
                previous.set(opened.session.beginOperation(TimeUnit.SECONDS.toNanos(2))!!)
                token.set(opened.session.beginOperation(TimeUnit.SECONDS.toNanos(2))!!)
            }
            val valid = token.get()
            listOf(valid.copy(captureGeneration = valid.captureGeneration + 1),
                valid.copy(sessionId = valid.sessionId + 1), valid.copy(operationId = valid.operationId + 1),
                valid.copy(deadlineNanos = valid.deadlineNanos + 1), previous.get()).forEach { bad ->
                accepted(opened.session.complete(bad, { discarded.incrementAndGet() }) { executed.incrementAndGet() })
            }
            await { discarded.get() == 5 }
            accepted(opened.session.complete(valid, { discarded.incrementAndGet() }) {
                assertTrue(it.owner.inEventLoop()); executed.incrementAndGet()
            })
            await { executed.get() == 1 }
            accepted(opened.session.complete(valid, { discarded.incrementAndGet() }) { fail("Duplicate operation result") })
            await { discarded.get() == 6 }
            onLoop(opened.session.owner) { assertNull(opened.session.snapshot().operationId); opened.session.close() }
            assertZero(group)
        } finally { opened.pipe.sink().close() }
    }

    @Test
    fun expiredCompletionCannotApplyEvenWhenItPrecedesTimerInLoopTurn() = withGroup { group ->
        val opened = open(group, 0)
        val token = AtomicReference<SocksSession.Operation>()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val discarded = AtomicInteger()
        try {
            onLoop(opened.session.owner) {
                request(opened.session); assertTrue(opened.session.admitProtocol(tcp))
                token.set(opened.session.beginOperation(TimeUnit.MILLISECONDS.toNanos(60))!!)
            }
            accepted(opened.session.owner.submit { entered.countDown(); release.await(3, TimeUnit.SECONDS) })
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            accepted(opened.session.complete(token.get(), { discarded.incrementAndGet() }) { fail("Expired operation") })
            Thread.sleep(120)
            release.countDown()
            await { discarded.get() == 1 && !opened.pipe.source().isOpen }
            onLoop(opened.session.owner) { assertCleared(opened.session) }
            assertZero(group)
        } finally { release.countDown(); opened.pipe.sink().close() }
    }

    @Test
    fun operationTimeoutWithoutWorkerClosesProtocolAndPromotionInvalidatesOldAuthToken() = withGroup { group ->
        val opened = open(group, 0)
        val auth = AtomicReference<SocksSession.Operation>()
        val discarded = AtomicInteger()
        try {
            onLoop(opened.session.owner) {
                request(opened.session)
                auth.set(opened.session.beginOperation(TimeUnit.SECONDS.toNanos(1))!!)
                assertTrue(opened.session.admitProtocol(udp))
            }
            accepted(opened.session.complete(auth.get(), { discarded.incrementAndGet() }) { fail() })
            await { discarded.get() == 1 }
            onLoop(opened.session.owner) { opened.session.beginOperation(TimeUnit.MILLISECONDS.toNanos(50)) }
            await { !opened.pipe.source().isOpen }
            assertZero(group)
        } finally { opened.pipe.sink().close() }
    }

    @Test
    fun completionQueueFullAndClosedOwnerDisposeResultExactlyOnce() = withGroup(config = smallConfig()) { group ->
        val opened = open(group, 0)
        val token = AtomicReference<SocksSession.Operation>()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val discarded = AtomicInteger()
        try {
            onLoop(opened.session.owner) { token.set(opened.session.beginOperation(TimeUnit.SECONDS.toNanos(2))!!) }
            accepted(opened.session.owner.submit { entered.countDown(); release.await(3, TimeUnit.SECONDS) })
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            repeat(2) { accepted(opened.session.complete(token.get(), { discarded.incrementAndGet() }) {}) }
            assertEquals(SocksEventLoop.Submission.QUEUE_FULL,
                opened.session.complete(token.get(), { discarded.incrementAndGet() }) { fail() })
            assertEquals(1, discarded.get())
            group.requestStop(); release.countDown(); assertTrue(group.shutdown())
            assertEquals(3, discarded.get())
            assertEquals(SocksEventLoop.Submission.STOPPED,
                opened.session.complete(token.get(), { discarded.incrementAndGet() }) { fail() })
            assertEquals(4, discarded.get())
            assertZero(group)
        } finally { release.countDown(); opened.pipe.sink().close() }
    }

    @Test
    fun directResourceCloseAndRepeatedSessionCloseWipeCapacityNotJustRemainingBytes() = withGroup { group ->
        val hooks = AtomicInteger()
        val opened = transfer(group.sessionAdmission.reserve(19, group.loop(0))!!,
            onClosed = { hooks.incrementAndGet() })
        val sibling = pipe()
        val buffers = mutableListOf<ByteBuffer>()
        try {
            onLoop(opened.session.owner) {
                request(opened.session); assertTrue(opened.session.admitProtocol(udp))
                repeat(2) { index ->
                    val buffer = opened.session.allocateControlBuffer(32)
                    buffer.put(ByteArray(32) { (index + 1).toByte() }); buffer.position(7); buffer.limit(8)
                    buffers.add(buffer)
                }
                // Mutable contents/position do not prevent identity-based release.
                opened.session.releaseControlBuffer(buffers[0])
                opened.session.releaseControlBuffer(buffers[0])
                assertEquals(32, opened.session.snapshot().bufferBytes)
                opened.session.register(sibling.source(), 0) { _, _ -> fail() }
                opened.session.beginOperation(TimeUnit.HOURS.toNanos(1))
                opened.session.resource.close(IOException("external scope close"))
                opened.session.close(); opened.session.close()
                assertCleared(opened.session)
                buffers.forEach { buffer ->
                    assertEquals(0, buffer.position()); assertEquals(buffer.capacity(), buffer.limit())
                    repeat(buffer.capacity()) { assertEquals(0.toByte(), buffer.get(it)) }
                }
            }
            assertEquals(1, hooks.get())
            assertFalse(opened.pipe.source().isOpen); assertFalse(sibling.source().isOpen)
            await { group.loop(0).stats().keys == 0 && group.loop(0).stats().timers == 0 }
            assertEquals(0, group.loop(0).stats().resources)
            assertZero(group)
        } finally { opened.pipe.sink().close(); sibling.source().close(); sibling.sink().close() }
    }

    @Test
    fun controlBufferBoundCannotBeBypassedAndWrongThreadCannotMutateSession() = withGroup { group ->
        val opened = open(group, 0)
        try {
            assertThrows(IllegalStateException::class.java) { opened.session.close() }
            assertThrows(IllegalStateException::class.java) { opened.session.snapshot() }
            assertThrows(IllegalStateException::class.java) { opened.session.allocateControlBuffer(1) }
            assertThrows(IllegalStateException::class.java) { opened.session.enterAuth() }
            assertThrows(IllegalStateException::class.java) { opened.session.beginOperation(1) }
            onLoop(group.loop(1)) { assertThrows(IllegalStateException::class.java) { opened.session.close() } }
            onLoop(opened.session.owner) {
                val buffer = opened.session.allocateControlBuffer(SocksSession.MAX_CONTROL_BUFFER_BYTES)
                assertThrows(IllegalArgumentException::class.java) { opened.session.allocateControlBuffer(1) }
                assertThrows(IllegalArgumentException::class.java) { opened.session.allocateControlBuffer(0) }
                opened.session.releaseControlBuffer(buffer)
                opened.session.allocateControlBuffer(1)
                opened.session.close()
                assertCleared(opened.session)
            }
            assertZero(group)
        } finally { opened.pipe.sink().close() }
    }

    @Test
    fun onSessionReadyAndWorkerCallbackFailureCloseTheRealScopeAndLeases() {
        repeat(3) { failureStage -> withGroup { group ->
            val channel = pipe()
            val closed = CountDownLatch(1)
            val created = AtomicReference<SocksSession>()
            try {
                accepted(group.sessionAdmission.reserve(1, group.loop(0))!!.transfer(channel.source(),
                    if (failureStage == 1) SelectionKey.OP_READ else 0,
                    { _, _, _ -> throw IOException("readiness") },
                    { session, _ ->
                        created.set(session)
                        session.allocateControlBuffer(16)
                        request(session); assertTrue(session.admitProtocol(tcp))
                        if (failureStage == 0) throw IOException("factory consumer")
                        if (failureStage == 2) {
                            val token = session.beginOperation(TimeUnit.SECONDS.toNanos(2))!!
                            accepted(session.complete(token) { throw IOException("worker consumer") })
                        }
                    }, { closed.countDown() }))
                if (failureStage == 1) channel.sink().write(ByteBuffer.wrap(byteArrayOf(1)))
                assertTrue(closed.await(2, TimeUnit.SECONDS))
                assertFalse(channel.source().isOpen)
                onLoop(group.loop(0)) { assertCleared(created.get()) }
                assertZero(group)
                assertEquals(SocksEventLoop.State.RUNNING, group.loop(0).stats().state)
            } finally { channel.source().close(); channel.sink().close() }
        } }
    }

    @Test
    fun additionalChannelRegisterFailureClosesSiblingTimersBuffersAndProtocolLease() = withGroup { group ->
        val opened = open(group, 0)
        val invalid = pipe()
        try {
            onLoop(opened.session.owner) {
                request(opened.session); assertTrue(opened.session.admitProtocol(tcp))
                opened.session.allocateControlBuffer(64).put(ByteArray(64) { 99 })
                opened.session.beginOperation(TimeUnit.HOURS.toNanos(1))
                assertThrows(IllegalArgumentException::class.java) {
                    opened.session.register(invalid.source(), SelectionKey.OP_CONNECT) { _, _ -> fail() }
                }
                assertCleared(opened.session)
                opened.session.close()
            }
            assertFalse(opened.pipe.source().isOpen); assertFalse(invalid.source().isOpen)
            assertZero(group)
            await { group.loop(0).stats().keys == 0 && group.loop(0).stats().timers == 0 }
        } finally { opened.pipe.sink().close(); invalid.source().close(); invalid.sink().close() }
    }

    @Test
    fun groupStopClosesSessionsOnBothOwnersAndClearsAllBuffersAndTimers() = withGroup { group ->
        val buffers = mutableListOf<ByteBuffer>()
        val opened = List(4) { index -> open(group, index % 2) }
        try {
            opened.forEachIndexed { index, item -> onLoop(item.session.owner) {
                if (index < 2) { request(item.session); assertTrue(item.session.admitProtocol(if (index == 0) tcp else udp)) }
                buffers.add(item.session.allocateControlBuffer(40).also { it.put(ByteArray(40) { 88 }) })
                item.session.beginOperation(TimeUnit.HOURS.toNanos(1))
            } }
            assertTrue(group.shutdown())
            assertZero(group)
            opened.forEach { assertFalse(it.pipe.source().isOpen) }
            buffers.forEach { repeat(it.capacity()) { index -> assertEquals(0.toByte(), it.get(index)) } }
            group.stats().forEach { stats ->
                assertEquals(0, stats.channels); assertEquals(0, stats.keys)
                assertEquals(0, stats.resources); assertEquals(0, stats.timers)
            }
        } finally { opened.forEach { it.pipe.sink().close() } }
    }

    @Test
    fun reservationTransferStopRaceNeverLeaksAcrossBothLoops() {
        repeat(20) { round -> withGroup { group ->
            val owner = group.loop(round % 2)
            val reservation = group.sessionAdmission.reserve(round.toLong(), owner)!!
            val channel = pipe()
            val start = CountDownLatch(1)
            val result = AtomicReference<SocksEventLoop.Submission>()
            val failure = AtomicReference<Throwable>()
            val closed = AtomicInteger()
            val handoff = Thread {
                try {
                    start.await()
                    result.set(reservation.transfer(channel.source(), 0, { _, _, _ -> fail() },
                        { session, _ -> session.allocateControlBuffer(16) }, { closed.incrementAndGet() }))
                } catch (error: Throwable) { failure.set(error) }
            }
            val stop = Thread { start.await(); group.requestStop() }
            try {
                handoff.start(); stop.start(); start.countDown()
                handoff.join(2_000); stop.join(2_000)
                assertFalse(handoff.isAlive); assertFalse(stop.isAlive)
                failure.get()?.let { throw it }
                assertTrue(group.shutdown())
                if (result.get() == SocksEventLoop.Submission.ACCEPTED) {
                    assertFalse(channel.source().isOpen); assertEquals(1, closed.get())
                } else {
                    assertEquals(SocksEventLoop.Submission.STOPPED, result.get())
                    assertTrue(channel.source().isOpen); assertEquals(0, closed.get())
                }
                reservation.close(); assertZero(group)
            } finally { channel.source().close(); channel.sink().close() }
        } }
    }

    @Test
    fun promotionStopRaceKeepsAuthenticationOrProtocolLeaseUntilOwnerClose() {
        repeat(20) { round -> withGroup { group ->
            val opened = open(group, round % 2)
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val done = CountDownLatch(1)
            val promoted = AtomicReference<Boolean>()
            val failure = AtomicReference<Throwable>()
            try {
                onLoop(opened.session.owner) { request(opened.session) }
                accepted(opened.session.owner.submit {
                    entered.countDown(); release.await(3, TimeUnit.SECONDS)
                    try {
                        promoted.set(opened.session.admitProtocol(if (round % 2 == 0) tcp else udp))
                        val snapshot = opened.session.snapshot()
                        assertEquals(!promoted.get(), snapshot.hasHandshakeLease)
                        assertEquals(promoted.get(), snapshot.hasProtocolLease)
                    } catch (error: Throwable) { failure.set(error) } finally { done.countDown() }
                })
                assertTrue(entered.await(2, TimeUnit.SECONDS))
                val stop = Thread { group.requestStop() }
                stop.start(); release.countDown(); stop.join(2_000); assertFalse(stop.isAlive)
                assertTrue(done.await(2, TimeUnit.SECONDS)); failure.get()?.let { throw it }
                assertTrue(group.shutdown()); assertZero(group)
                assertFalse(opened.pipe.source().isOpen)
            } finally { release.countDown(); opened.pipe.sink().close() }
        } }
    }

    @Test
    fun slowStartupStopAndPartialStartupFailureNeverAdmitSessions() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val opened = Collections.synchronizedList(mutableListOf<Selector>())
        val group = SocksEventLoopGroup(selectorFactory = { index ->
            if (index == 1) { entered.countDown(); release.await(3, TimeUnit.SECONDS) }
            Selector.open().also { opened.add(it) }
        })
        val failed = AtomicReference<Throwable>()
        val starter = Thread { try { group.start() } catch (error: Throwable) { failed.set(error) } }
        try {
            assertNull(group.sessionAdmission.reserve(1))
            starter.start(); assertTrue(entered.await(2, TimeUnit.SECONDS))
            // Loop 0 is RUNNING but the group is STARTING: no early admissions.
            assertEquals(SocksEventLoop.State.RUNNING, group.loop(0).stats().state)
            assertNull(group.sessionAdmission.reserve(1, group.loop(0)))
            group.requestStop(); assertZero(group); release.countDown()
            starter.join(3_000); assertFalse(starter.isAlive); assertNotNull(failed.get())
            assertTrue(group.shutdown()); assertZero(group)
            assertTrue(opened.all { !it.isOpen })
        } finally { release.countDown(); group.shutdown() }
        val broken = SocksEventLoopGroup(selectorFactory = { index ->
            if (index == 1) throw IOException("second selector") else Selector.open()
        })
        try {
            assertThrows(IOException::class.java) { broken.start() }
            assertNull(broken.sessionAdmission.reserve(1))
            assertTrue(broken.shutdown()); assertZero(broken)
        } finally { broken.shutdown() }
    }

    @Test
    fun reservationOwnerAndTimeoutAreValidatedAndCannotMigrate() = withGroup { group ->
        val foreign = SocksEventLoop("foreign")
        try {
            assertThrows(IllegalArgumentException::class.java) { group.sessionAdmission.reserve(1, foreign) }
            assertThrows(IllegalArgumentException::class.java) { group.sessionAdmission.reserve(1, group.loop(0), 0) }
            assertThrows(IllegalArgumentException::class.java) {
                group.sessionAdmission.reserve(1, group.loop(0), SocksSessionAdmission.DEFAULT_HANDSHAKE_TIMEOUT_NANOS + 1)
            }
            val first = group.sessionAdmission.reserve(1)!!
            val second = group.sessionAdmission.reserve(1)!!
            assertNotSame(first.owner, second.owner)
            assertNotEquals(first.sessionId, second.sessionId)
            first.close(); second.close(); assertZero(group)
        } finally { foreign.close() }
    }

    @Test
    fun acceptedSocketChannelUsesTransferResourceAndOwnerCallbackClosesLease() = withGroup { group ->
        val listener = ServerSocketChannel.open()
        val client = SocketChannel.open()
        val closed = CountDownLatch(1)
        try {
            listener.bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
            // Test fixture only, not a NIO-104 production listener implementation.
            val reservation = group.sessionAdmission.reserve(21, group.loop(1))!!
            client.connect(listener.localAddress)
            val acceptedChannel = listener.accept()
            acceptedChannel.configureBlocking(false)
            accepted(reservation.transfer(acceptedChannel, SelectionKey.OP_READ,
                { session, registration, _ ->
                    val input = session.allocateControlBuffer(8)
                    assertEquals(1, (registration.channel as SocketChannel).read(input))
                    assertEquals(42.toByte(), input.get(0))
                    request(session); assertTrue(session.admitProtocol(tcp))
                    session.close()
                }, { session, registration -> assertSame(session.resource, registration.resource) },
                { closed.countDown() }))
            client.write(ByteBuffer.wrap(byteArrayOf(42)))
            assertTrue(closed.await(2, TimeUnit.SECONDS))
            assertFalse(acceptedChannel.isOpen); assertZero(group)
        } finally { client.close(); listener.close() }
    }

    @Test
    fun completionAfterResourceCloseRejectsAndDisposesOnSubmittingThread() = withGroup { group ->
        val opened = open(group, 0)
        val token = AtomicReference<SocksSession.Operation>()
        val discarded = AtomicInteger()
        val submitter = Thread.currentThread()
        try {
            onLoop(opened.session.owner) {
                token.set(opened.session.beginOperation(TimeUnit.SECONDS.toNanos(2))!!)
                opened.session.resource.close()
            }
            assertEquals(SocksEventLoop.Submission.OWNER_CLOSED, opened.session.complete(token.get(), {
                assertSame(submitter, Thread.currentThread()); discarded.incrementAndGet()
            }) { fail() })
            assertEquals(1, discarded.get()); assertZero(group)
        } finally { opened.pipe.sink().close() }
    }

    @Test
    fun transferredLeaseIsReleasedWhenChosenLoopStopsBeforeAdmissionTransfer() = withGroup { group ->
        val owner = group.loop(0)
        val reservation = group.sessionAdmission.reserve(1, owner)!!
        val channel = pipe()
        try {
            owner.requestStop()
            assertEquals(SocksEventLoop.Submission.STOPPED,
                reservation.transfer(channel.source(), 0, { _, _, _ -> fail() }, { _, _ -> fail() }, { fail() }))
            assertTrue(channel.source().isOpen); assertZero(group)
            // No automatic group failover/migration to loop 1.
            assertEquals(SocksEventLoop.State.RUNNING, group.loop(1).stats().state)
        } finally { channel.source().close(); channel.sink().close() }
    }

    @Test
    fun resourceStopClearsScopedTimerOwnerAndCallbackReferences() = withGroup { group ->
        val opened = open(group, 0)
        val timer = AtomicReference<SocksEventLoop.Timer>()
        try {
            onLoop(opened.session.owner) {
                timer.set(opened.session.owner.schedule(TimeUnit.HOURS.toNanos(1), opened.session.resource) {
                    fail("Scope timer fired")
                }.timer!!)
                assertTrue(timer.get().retainsCallback())
                opened.session.close()
                assertFalse(timer.get().retainsCallback())
                assertFalse(timer.get().cancel())
            }
            assertZero(group)
        } finally { opened.pipe.sink().close() }
    }

    @Test
    fun monotonicDeadlineAndOperationValidationSurviveLongWrapWithoutReset() {
        val clock = AtomicLong(Long.MAX_VALUE - TimeUnit.SECONDS.toNanos(1))
        withGroup(sessionNanoClock = clock::get) { group ->
            val admission = group.sessionAdmission
            val opened = transfer(admission.reserve(30, group.loop(0))!!)
            val token = AtomicReference<SocksSession.Operation>()
            val discarded = AtomicInteger()
            try {
                onLoop(opened.session.owner) {
                    request(opened.session)
                    assertTrue(opened.session.snapshot().deadlineNanos!! < 0) // total deadline wraps
                    token.set(opened.session.beginOperation(TimeUnit.SECONDS.toNanos(2))!!)
                    clock.addAndGet(TimeUnit.SECONDS.toNanos(3))
                }
                accepted(opened.session.complete(token.get(), { discarded.incrementAndGet() }) { fail() })
                await { discarded.get() == 1 }
                onLoop(opened.session.owner) { assertCleared(opened.session) }
                assertEquals(0, admission.stats().handshakes.current)
                assertEquals(0, admission.stats().pendingReservations)
            } finally { opened.pipe.sink().close() }
        }
    }

    @Test
    fun reserveStopRaceRevokesAnyReservationWithoutNegativeCounters() {
        repeat(20) { round -> withGroup { group ->
            val start = CountDownLatch(1)
            val reservation = AtomicReference<SocksSessionAdmission.Reservation>()
            val failure = AtomicReference<Throwable>()
            val reserve = Thread {
                try { start.await(); reservation.set(group.sessionAdmission.reserve(round.toLong())) }
                catch (error: Throwable) { failure.set(error) }
            }
            val stop = Thread { start.await(); group.requestStop() }
            reserve.start(); stop.start(); start.countDown()
            reserve.join(2_000); stop.join(2_000)
            assertFalse(reserve.isAlive); assertFalse(stop.isAlive)
            failure.get()?.let { throw it }
            reservation.get()?.close(); assertTrue(group.shutdown()); assertZero(group)
        } }
    }

    @Test
    fun throwingExternalCleanupCannotLeakSessionBuffersOrLeases() = withGroup { group ->
        val opened = open(group, 0)
        try {
            onLoop(opened.session.owner) {
                request(opened.session)
                assertTrue(opened.session.admitProtocol(SocksSessionAdmission.Protocol.TCP))
                opened.session.allocateControlBuffer(32)
                val token = opened.session.beginOperation(TimeUnit.SECONDS.toNanos(2))!!
                opened.session.attachOperationCleanup(token, AutoCloseable { throw AssertionError("controlled cleanup") })
                opened.session.close()
                assertCleared(opened.session)
                assertEquals(1L, opened.session.snapshot().operationCleanupFailures)
                opened.session.close()
                assertEquals(1L, opened.session.snapshot().operationCleanupFailures)
            }
            assertZero(group)
        } finally { opened.pipe.sink().close() }
    }

    private data class Opened(val session: SocksSession, val pipe: Pipe)

    private fun open(group: SocksEventLoopGroup, index: Int): Opened =
        transfer(group.sessionAdmission.reserve(19, group.loop(index))!!)

    private fun transfer(
        reservation: SocksSessionAdmission.Reservation,
        onSession: (SocksSession, SocksEventLoop.Registration) -> Unit = { _, _ -> },
        onClosed: (Throwable?) -> Unit = {}
    ): Opened {
        val channel = pipe()
        val done = CountDownLatch(1)
        val session = AtomicReference<SocksSession>()
        val error = AtomicReference<Throwable>()
        accepted(reservation.transfer(channel.source(), 0, { _, _, _ -> fail("No interests") }, { created, registration ->
            try {
                assertTrue(reservation.owner.inEventLoop())
                assertSame(reservation.owner, created.owner)
                assertSame(registration.resource, created.resource)
                session.set(created); onSession(created, registration)
            } catch (failure: Throwable) { error.set(failure); throw failure } finally { done.countDown() }
        }, onClosed))
        assertTrue(done.await(2, TimeUnit.SECONDS))
        error.get()?.let { throw it }
        return Opened(session.get(), channel)
    }

    private fun request(session: SocksSession) {
        assertTrue(session.enterAuth()); assertTrue(session.enterRequest())
    }

    private fun assertCleared(session: SocksSession) {
        val snapshot = session.snapshot()
        assertEquals(SocksSession.State.CLOSED, snapshot.state)
        assertEquals(0, snapshot.buffers); assertEquals(0, snapshot.bufferBytes)
        assertNull(snapshot.deadlineNanos); assertNull(snapshot.operationId)
        assertFalse(snapshot.hasHandshakeLease); assertFalse(snapshot.hasProtocolLease)
    }

    private fun assertZero(group: SocksEventLoopGroup) {
        val stats = group.sessionAdmission.stats()
        assertEquals(stats.toString(), 0, stats.handshakes.current)
        assertEquals(stats.toString(), 0, stats.tcp.current)
        assertEquals(stats.toString(), 0, stats.udp.current)
        assertEquals(stats.toString(), 0, stats.pendingReservations)
    }

    private fun pipe(): Pipe = Pipe.open().also { it.source().configureBlocking(false) }
    private fun accepted(result: SocksEventLoop.Submission) = assertEquals(SocksEventLoop.Submission.ACCEPTED, result)
    private fun smallConfig() = SocksEventLoopConfig(commandCapacity = 2, completionCapacity = 2,
        commandsPerTurn = 1, completionsPerTurn = 1)

    private fun withGroup(
        limits: SocksSessionLimits = SocksSessionLimits(),
        config: SocksEventLoopConfig = SocksEventLoopConfig(),
        sessionNanoClock: () -> Long = System::nanoTime,
        action: (SocksEventLoopGroup) -> Unit
    ) {
        val group = SocksEventLoopGroup(config = config, sessionLimits = limits, sessionNanoClock = sessionNanoClock)
        group.start()
        try { action(group) } finally {
            assertTrue(group.shutdown()); assertZero(group)
            group.stats().forEach { stats ->
                assertEquals(SocksEventLoop.State.TERMINATED, stats.state)
                assertEquals(0, stats.resources); assertEquals(0, stats.channels)
                assertEquals(0, stats.keys); assertEquals(0, stats.timers)
                assertEquals(0, stats.commands); assertEquals(0, stats.completions)
                assertEquals(0L, stats.cleanupFailures)
            }
        }
    }

    private fun onLoop(loop: SocksEventLoop, action: () -> Unit) {
        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable>()
        accepted(loop.submit {
            try { action() } catch (failure: Throwable) { error.set(failure) } finally { done.countDown() }
        })
        assertTrue("Owner callback did not finish: ${loop.stats()}", done.await(3, TimeUnit.SECONDS))
        error.get()?.let { throw AssertionError("Owner assertion failed", it) }
    }

    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (!condition()) {
            if (deadline - System.nanoTime() <= 0) fail("Timed out")
            Thread.sleep(2)
        }
    }
}
