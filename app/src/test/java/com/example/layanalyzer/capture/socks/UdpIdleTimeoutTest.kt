package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.UdpDestinationPolicy
import com.example.layanalyzer.capture.UdpVerdict
import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.SocksUdpRequest
import java.io.IOException
import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class UdpIdleTimeoutTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val dns = UdpIdleTimeout.DNS_IDLE_NANOS
    private val udp = UdpIdleTimeout.UDP_IDLE_NANOS

    @Test fun unusedAssociationExpiresOnDefaultOneSecondTimerWithoutChannelReadiness() {
        Fixture(interval = UdpIdleTimeout.CHECK_INTERVAL_NANOS).use { f -> f.link().use { link ->
            val timers = link.owner.stats().firedTimers
            link.onOwner {
                assertEquals(1, link.owner.stats().timers)
                f.now.set(link.initial + dns)
            }
            link.expectIdle(dns)
            assertTrue(link.owner.stats().firedTimers > timers)
        } }
    }

    @Test fun legalDnsAtLastNanosecondRefreshesAndOldTimerCannotCloseIt() {
        Fixture().use { f -> f.link().use { link ->
            link.time(link.initial + dns - 1)
            link.send(53)
            link.await { it.policy.sentBytes == 1L }
            link.onOwner { assertEquals(link.initial + dns - 1, link.driver.policy.activity().lastActivityNanos) }
            link.time(link.initial + dns)
            link.assertOpenAfterTimer()
            link.time(link.initial + 2 * dns - 1)
            link.expectIdle(dns)
        } }
    }

    @Test fun ordinaryUdpUsesSixtySecondsAndLaterDnsCannotRevertIt() {
        Fixture().use { f -> f.link().use { link -> endpoint().use { upstream ->
            link.send(upstream.localPort)
            receive(upstream)
            link.await { it.policy.sentBytes == 1L }
            link.time(link.initial + 50_000_000_000L)
            link.assertOpenAfterTimer()
            link.send(53)
            link.await { it.policy.sentBytes == 2L }
            link.onOwner { assertFalse(link.driver.policy.activity().dnsOnly) }
            link.time(link.initial + 50_000_000_000L + udp - 1)
            link.assertOpenAfterTimer()
            link.time(link.initial + 50_000_000_000L + udp)
            link.expectIdle(udp)
        } } }
    }

    @Test fun exactDeadlineDatagramCannotReviveUnusedAssociationOrBecomeOrdinaryUdp() {
        val reads = AtomicInteger()
        Fixture(interval = 1_000_000_000, io = object : UdpDataPlane.ChannelIo {
            override fun receive(channel: DatagramChannel, scratch: ByteBuffer): InetSocketAddress? {
                reads.incrementAndGet()
                return super.receive(channel, scratch)
            }
        }).use { f -> f.link().use { link ->
            link.time(link.initial + dns)
            link.send(9999)
            link.expectIdle(dns)
            assertEquals(0, reads.get())
            link.onOwner {
                assertEquals(link.initial, link.driver.policy.activity().lastActivityNanos)
                assertTrue(link.driver.policy.activity().dnsOnly)
            }
        } }
    }

    @Test fun clockCrossingDeadlineDuringReceiveClosesBeforePolicyRefresh() {
        val now = AtomicLong(100)
        val cross = AtomicBoolean()
        Fixture(now = now, io = object : UdpDataPlane.ChannelIo {
            override fun receive(channel: DatagramChannel, scratch: ByteBuffer): InetSocketAddress? {
                val result = super.receive(channel, scratch)
                if (result != null && cross.get()) now.set(100 + dns)
                return result
            }
        }).use { f -> f.link().use { link ->
            link.time(link.initial + dns - 1)
            cross.set(true)
            link.send(53)
            link.expectIdle(dns)
            link.onOwner { assertEquals(link.initial, link.driver.policy.activity().lastActivityNanos) }
        } }
    }

    @Test fun admissionAndRefreshUseSameSampleWhenClockCrossesImmediatelyAfterSample() {
        val now = AtomicLong(100)
        val afterSample = AtomicReference<(() -> Unit)?>(null)
        Fixture(now = now, afterSample = afterSample, io = object : UdpDataPlane.ChannelIo {
            override fun receive(channel: DatagramChannel, scratch: ByteBuffer): InetSocketAddress? {
                val result = super.receive(channel, scratch)
                if (result != null) afterSample.set { now.set(100 + dns) }
                return result
            }
        }).use { f -> f.link().use { link ->
            link.time(link.initial + dns - 1)
            link.send(53)
            link.await { it.policy.sentBytes == 1L }
            link.onOwner {
                assertEquals(link.initial + dns - 1, link.driver.policy.activity().lastActivityNanos)
                assertEquals(SocksSession.State.UDP_ACTIVE, link.active.session.snapshot().state)
            }
            link.time(link.initial + 2 * dns - 1)
            link.expectIdle(dns)
        } }
    }

    @Test fun malformedAndForeignClientPacketsDoNotRefreshActivity() {
        Fixture().use { f -> f.link().use { link -> endpoint().use { foreign ->
            link.send(53)
            link.await { it.policy.sentBytes == 1L }
            link.time(link.initial + dns - 1)
            link.raw(byteArrayOf(0, 0, 1))
            val wire = SocksProtocol.encodeUdpRequest(SocksUdpRequest(SocksDestination.Ip(loopback), 53, byteArrayOf(1)))
            foreign.send(DatagramPacket(wire, wire.size, loopback, link.relayPort))
            link.await { it.policy.invalidDatagrams == 1L && it.policy.sourceRejectedDatagrams == 1L }
            link.onOwner { assertEquals(link.initial, link.driver.policy.activity().lastActivityNanos) }
            link.time(link.initial + dns)
            link.expectIdle(dns)
        } } }
    }

    @Test fun forgedUpstreamResponseDoesNotRefreshAndCannotKeepAssociationAlive() {
        Fixture().use { f -> f.link().use { link -> endpoint().use { forged ->
            link.time(link.initial + dns - 1)
            forged.send(DatagramPacket(byteArrayOf(1), 1, link.upstreamAddress))
            link.await { it.policy.unallowedResponses == 1L }
            link.time(link.initial + dns)
            link.expectIdle(dns)
        } } }
    }

    @Test fun allowedResponseRefreshesBeforeBoundaryAndExpiresSixtySecondsLater() {
        Fixture().use { f -> f.link().use { link -> endpoint().use { upstream ->
            link.send(upstream.localPort)
            val request = receive(upstream)
            link.time(link.initial + udp - 1)
            upstream.send(DatagramPacket(byteArrayOf(4), 1, request.socketAddress))
            assertArrayEquals(byteArrayOf(4), link.response())
            link.onOwner { assertEquals(link.initial + udp - 1, link.driver.policy.activity().lastActivityNanos) }
            link.time(link.initial + udp)
            link.assertOpenAfterTimer()
            link.time(link.initial + 2 * udp - 1)
            link.expectIdle(udp)
        } } }
    }

    @Test fun allowedResponseAtExactDeadlineIsNotDeliveredOrCountedAsActivity() {
        Fixture(interval = 1_000_000_000).use { f -> f.link().use { link -> endpoint().use { upstream ->
            link.send(upstream.localPort)
            val request = receive(upstream)
            link.await { it.policy.sentBytes == 1L }
            link.time(link.initial + udp)
            upstream.send(DatagramPacket(byteArrayOf(4), 1, request.socketAddress))
            link.expectIdle(udp)
            link.onOwner { assertEquals(0L, link.driver.policy.stats().receivedBytes) }
            link.client.soTimeout = 60
            assertThrows(SocketTimeoutException::class.java) { receive(link.client) }
        } } }
    }

    @Test fun blockedLegalNonDnsStillPermanentlySelectsOrdinaryIdlePolicy() {
        Fixture(rule = UdpDestinationPolicy { _, _ -> UdpVerdict.BlockSelectedUdp443 }).use { f -> f.link().use { link ->
            link.time(link.initial + dns - 1)
            link.send(443)
            link.await { it.policy.intervention.blockedDatagrams == 1L }
            link.onOwner { assertFalse(link.driver.policy.activity().dnsOnly) }
            link.time(link.initial + dns - 1 + udp - 1)
            link.assertOpenAfterTimer()
            link.time(link.initial + dns - 1 + udp)
            link.expectIdle(udp)
        } }
    }

    @Test fun controlBytesNeverRefreshActivityOrChangeDnsClassification() {
        Fixture().use { f -> f.link().use { link ->
            link.time(link.initial + dns - 1)
            val callbacks = link.owner.stats().readinessCallbacks
            link.control.getOutputStream().write(ByteArray(100) { 7 })
            await { link.owner.stats().readinessCallbacks > callbacks }
            link.onOwner {
                assertEquals(link.initial, link.driver.policy.activity().lastActivityNanos)
                assertTrue(link.driver.policy.activity().dnsOnly)
            }
            link.time(link.initial + dns)
            link.expectIdle(dns)
        } }
    }

    @Test fun dnsCompletionAndSubsequentSendDoNotRefreshActivity() {
        val release = CountDownLatch(1)
        Fixture(lookup = { assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback) }).use { f ->
            try { f.link().use { link -> endpoint().use { upstream ->
                link.send(upstream.localPort, SocksDestination.Domain("refresh.test"))
                await { f.resolver.stats().activeLookups == 1 }
                link.time(link.initial + 9_000_000_000)
                release.countDown()
                receive(upstream)
                link.await { it.queuedPackets == 0 && it.policy.sentBytes == 1L }
                link.onOwner { assertEquals(link.initial, link.driver.policy.activity().lastActivityNanos) }
                link.time(link.initial + udp)
                link.expectIdle(udp)
            } } } finally { release.countDown() }
        }
    }

    @Test fun dnsCompletionAtIdleBoundaryCannotSendOrResurrectAndReleasesQueuedPackets() {
        val release = CountDownLatch(1)
        val sends = AtomicInteger()
        Fixture(interval = 1_000_000_000, io = object : UdpDataPlane.ChannelIo {
            override fun send(channel: DatagramChannel, bytes: ByteBuffer, target: InetSocketAddress): Int {
                sends.incrementAndGet()
                return super.send(channel, bytes, target)
            }
        }, lookup = { assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback) }).use { f ->
            try { f.link().use { link ->
                link.send(53, SocksDestination.Domain("deadline.test"))
                await { f.resolver.stats().activeLookups == 1 }
                link.send(53)
                link.await { it.queuedPackets == 2 }
                link.time(link.initial + dns)
                release.countDown()
                link.expectIdle(dns)
                await { f.resolver.stats().activeLookups == 0 }
                assertEquals(0, sends.get())
                link.onOwner { assertEquals(link.initial, link.driver.policy.activity().lastActivityNanos) }
            } } finally { release.countDown() }
        }
    }

    @Test fun pendingDnsIsCanceledOnIdleBeforeBlockedWorkerReturns() {
        val release = CountDownLatch(1)
        Fixture(lookup = { assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback) }).use { f ->
            try { f.link().use { link ->
                link.send(53, SocksDestination.Domain("idle.test"))
                await { f.resolver.stats().activeLookups == 1 }
                link.time(link.initial + dns)
                link.expectIdle(dns)
                assertEquals(1, f.resolver.stats().activeLookups)
                assertEquals(0, f.resolver.stats().subscribers)
                release.countDown()
                await { f.resolver.stats().activeLookups == 0 }
                assertEquals(1L, f.resolver.stats().abandonedResults)
            } } finally { release.countDown() }
        }
    }

    @Test fun queuedZeroWriteCompletionDoesNotRenewIdle() {
        val blocked = AtomicBoolean(true)
        Fixture(io = object : UdpDataPlane.ChannelIo {
            override fun send(channel: DatagramChannel, bytes: ByteBuffer, target: InetSocketAddress): Int =
                if (blocked.get()) 0 else super.send(channel, bytes, target)
        }).use { f -> f.link().use { link -> endpoint().use { upstream ->
            link.send(upstream.localPort)
            link.await { it.retryPending }
            link.time(link.initial + udp - 1)
            blocked.set(false)
            receive(upstream)
            link.await { it.queuedPackets == 0 }
            link.onOwner { assertEquals(link.initial, link.driver.policy.activity().lastActivityNanos) }
            link.time(link.initial + udp)
            link.expectIdle(udp)
        } } }
    }

    @Test fun clockCrossingDeadlineDuringSendClosesWithoutAnotherSendAttempt() {
        val now = AtomicLong(100)
        val cross = AtomicBoolean()
        val attempts = AtomicInteger()
        Fixture(now = now, io = object : UdpDataPlane.ChannelIo {
            override fun send(channel: DatagramChannel, bytes: ByteBuffer, target: InetSocketAddress): Int {
                attempts.incrementAndGet()
                if (cross.get()) now.set(100 + dns)
                return 0
            }
        }).use { f -> f.link().use { link ->
            cross.set(true)
            link.send(53)
            link.expectIdle(dns)
            assertEquals(1, attempts.get())
        } }
    }

    @Test fun idleDuringZeroWriteRetryReleasesWholeQueueAndCancelsTimers() {
        Fixture(io = object : UdpDataPlane.ChannelIo {
            override fun send(channel: DatagramChannel, bytes: ByteBuffer, target: InetSocketAddress) = 0
        }).use { f -> f.link().use { link ->
            repeat(8) { link.send(53) }
            link.await { it.queuedPackets == 8 && it.retryPending }
            link.time(link.initial + dns)
            link.expectIdle(dns)
            assertEquals(0, f.runtime.snapshot().queuedPackets)
            assertEquals(0, f.runtime.snapshot().scratchBuffers)
        } }
    }

    @Test fun sendFailureDoesNotRenewIdleOrReplaceExpiryReason() {
        val now = AtomicLong(100)
        Fixture(now = now, io = object : UdpDataPlane.ChannelIo {
            override fun send(channel: DatagramChannel, bytes: ByteBuffer, target: InetSocketAddress): Int {
                now.set(100 + dns - 1)
                throw IOException("controlled send failure")
            }
        }).use { f -> f.link().use { link ->
            link.send(53)
            link.await { it.policy.sendFailures == 1L }
            link.onOwner { assertEquals(link.initial, link.driver.policy.activity().lastActivityNanos) }
            link.time(link.initial + dns)
            link.expectIdle(dns)
        } }
    }

    @Test fun nanoTimeWrapKeepsExactTenAndSixtySecondBoundaries() {
        for (ordinary in listOf(false, true)) {
            Fixture(now = AtomicLong(Long.MAX_VALUE - 5_000_000_000L)).use { f -> f.link().use { link ->
                val limit = if (ordinary) udp else dns
                if (ordinary) {
                    link.send(9999)
                    link.await { it.policy.sentBytes == 1L }
                }
                link.time(link.initial + limit - 1)
                link.assertOpenAfterTimer()
                link.time(link.initial + limit)
                link.expectIdle(limit)
            } }
        }
    }

    @Test fun controlEofCancelsTimerAndDnsWithoutWaitingForWorker() {
        val release = CountDownLatch(1)
        Fixture(lookup = { assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback) }).use { f ->
            try { f.link().use { link ->
                link.send(53, SocksDestination.Domain("eof.test"))
                await { f.resolver.stats().activeLookups == 1 }
                link.control.shutdownOutput()
                assertEquals(-1, link.control.getInputStream().read())
                link.assertCleaned()
                assertEquals(1, f.resolver.stats().activeLookups)
            } } finally { release.countDown() }
        }
    }

    @Test fun stopWithDnsAndQueuedSendsCancelsAllIdleTimersWithoutWaiting() {
        val release = CountDownLatch(1)
        Fixture(io = object : UdpDataPlane.ChannelIo {
            override fun send(channel: DatagramChannel, bytes: ByteBuffer, target: InetSocketAddress) = 0
        }, lookup = { assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback) }).use { f ->
            try { f.link().use { first -> f.link().use { second ->
                first.send(53, SocksDestination.Domain("stop.test"))
                await { f.resolver.stats().activeLookups == 1 }
                second.send(53)
                second.await { it.retryPending }
                assertTrue(f.server.stop())
                assertEquals(1, f.resolver.stats().activeLookups)
                assertEquals(0, f.resolver.stats().subscribers)
                assertEquals(0, f.server.stats().loops.sumOf { it.timers })
                assertEquals(0, f.runtime.snapshot().queuedBytes)
                assertEquals(-1, first.control.getInputStream().read())
                assertEquals(-1, second.control.getInputStream().read())
            } } } finally { release.countDown() }
        }
    }

    @Test fun scopeAndRuntimeInvalidationAreDetectedByTimerWithoutIo() {
        for (closeScope in listOf(true, false)) {
            Fixture().use { f -> f.link().use { link ->
                if (closeScope) f.scope.close() else f.runtime.close()
                assertEquals(-1, link.control.getInputStream().read())
                link.assertCleaned()
            } }
        }
    }

    @Test fun initialTimerRejectionCleansPartiallyInstalledLifecycle() {
        Fixture(config = SocksEventLoopConfig(timerCapacity = 1, timersPerTurn = 1), beforeAttach = { active, _ ->
            assertEquals(SocksEventLoop.Submission.ACCEPTED,
                active.session.owner.schedule(30_000_000_000, active.session.resource) {}.result)
        }).use { f -> f.link().use { link ->
            assertEquals(-1, link.control.getInputStream().read())
            link.assertCleaned()
            link.onOwner {
                val cause = link.active.session.snapshot().closeCause
                assertTrue(cause is SocksSession.SchedulingRejectedException)
                assertTrue(cause!!.message!!.contains("TIMER_FULL"))
                link.idle.close()
                link.active.close()
            }
        } }
    }

    @Test fun periodicTimerRearmRejectionClosesAndReportsReason() {
        val afterSample = AtomicReference<(() -> Unit)?>(null)
        Fixture(interval = 100_000_000, afterSample = afterSample,
            config = SocksEventLoopConfig(timerCapacity = 1, timersPerTurn = 1)).use { f -> f.link().use { link ->
            link.onOwner {
                afterSample.set {
                    assertEquals(SocksEventLoop.Submission.ACCEPTED,
                        link.owner.schedule(30_000_000_000, link.active.session.resource) {}.result)
                }
            }
            assertEquals(-1, link.control.getInputStream().read())
            link.assertCleaned()
            link.onOwner { assertTrue(link.active.session.snapshot().closeCause is SocksSession.SchedulingRejectedException) }
        } }
    }

    @Test fun alreadyClosedDataPlaneDoesNotInstallTimerOrThrowDuringAssembly() {
        Fixture(beforeAttach = { active, _ -> active.close() }).use { f -> f.link().use { link ->
            link.onOwner {
                assertEquals(0, link.owner.stats().timers)
                link.active.close()
            }
            assertEquals(-1, link.control.getInputStream().read())
            link.assertCleaned()
        } }
    }

    @Test fun lifecycleMethodsRequireOwnerAndDuplicateInstallationKeepsOriginalTimer() {
        Fixture().use { f -> f.link().use { link ->
            assertThrows(IllegalStateException::class.java) { link.idle.beforeIo(f.now.get()) }
            assertThrows(IllegalStateException::class.java) { link.idle.close() }
            assertThrows(IllegalStateException::class.java) { link.driver.checkActive() }
            link.onOwner {
                assertThrows(IllegalStateException::class.java) { UdpIdleTimeout.attach(link.active, link.driver) }
                assertEquals(1, link.owner.stats().timers)
                assertThrows(IllegalArgumentException::class.java) { UdpIdleTimeout.attach(link.active, link.driver, 0) }
                link.active.close()
                link.idle.close()
                link.idle.close()
            }
            link.assertCleaned()
        } }
    }

    private inner class Fixture(
        val now: AtomicLong = AtomicLong(100),
        afterSample: AtomicReference<(() -> Unit)?> = AtomicReference(null),
        interval: Long = 10_000_000,
        io: UdpDataPlane.ChannelIo = UdpDataPlane.ChannelIo.CHANNEL,
        config: SocksEventLoopConfig = SocksEventLoopConfig(),
        rule: UdpDestinationPolicy = UdpDestinationPolicy.PRESERVE,
        beforeAttach: (UdpAssociation.Active, UdpDataPlane) -> Unit = { _, _ -> },
        lookup: (String) -> Array<InetAddress> = { arrayOf(loopback) }
    ) : AutoCloseable {
        val runtime = UdpDataPlaneRuntime()
        val resolver = SocksResolver.forTest()
        lateinit var scope: SocksResolver.Scope
        val established = LinkedBlockingQueue<Established>()
        val association = UdpAssociation({}, { active ->
            val driver = UdpDataPlane(active, runtime, scope, rule, io)
            val port = ((active.relay.channel as DatagramChannel).localAddress as InetSocketAddress).port
            val upstream = (active.upstream.channel as DatagramChannel).localAddress as InetSocketAddress
            val initial = driver.policy.activity().lastActivityNanos
            beforeAttach(active, driver)
            val idle = UdpIdleTimeout.attach(active, driver, interval)
            established.add(Established(active, driver, idle, port, upstream, initial))
        })
        val server = SocksNioServer(SocksNioHandshake({ SocksCredentials.of("u", "p") }, association::start),
            config = config,
            sessionNanoClock = { val sampled = now.get(); afterSample.getAndSet(null)?.invoke(); sampled },
            onRunStarting = { generation -> scope = resolver.newScope(generation, 1, lookup) },
            onRunStopping = { runtime.close(); scope.close() }).also { it.start() }

        fun link(): Link {
            val control = Socket(loopback, server.stats().port!!).apply { soTimeout = 3000 }
            control.getOutputStream().write(byteArrayOf(5, 1, 2, 1, 1, 'u'.code.toByte(), 1, 'p'.code.toByte()) +
                SocksProtocol.encodeRequest(SocksRequest(3, SocksDestination.Ip(loopback), 0)))
            val reply = ByteArray(14)
            DataInputStream(control.getInputStream()).readFully(reply)
            assertArrayEquals(byteArrayOf(5, 2, 1, 0, 5, 0, 0, 1), reply.copyOf(8))
            return Link(this, control, checkNotNull(established.poll(3, TimeUnit.SECONDS)))
        }

        override fun close() {
            assertTrue(server.stop())
            assertTrue(resolver.shutdownForTest())
            assertEquals(0, runtime.snapshot().associations)
            assertEquals(0, runtime.snapshot().queuedPackets)
            assertEquals(0, runtime.snapshot().queuedBytes)
            assertEquals(0, runtime.snapshot().scratchBuffers)
            assertEquals(0, scope.stats().subscribers)
            assertEquals(0, server.stats().admission!!.udp.current)
            assertEquals(0, server.stats().admission!!.handshakes.current)
            server.stats().loops.forEach {
                assertEquals(0, it.channels)
                assertEquals(0, it.keys)
                assertEquals(0, it.resources)
                assertEquals(0, it.timers)
                assertEquals(0, it.commands)
                assertEquals(0, it.completions)
                assertEquals(0L, it.callbackFailures)
                assertEquals(0L, it.cleanupFailures)
            }
        }
    }

    private data class Established(val active: UdpAssociation.Active, val driver: UdpDataPlane,
        val idle: UdpIdleTimeout, val port: Int, val upstream: InetSocketAddress, val initial: Long)

    private inner class Link(val fixture: Fixture, val control: Socket, established: Established) : AutoCloseable {
        val active = established.active
        val driver = established.driver
        val idle = established.idle
        val relayPort = established.port
        val upstreamAddress = InetSocketAddress(loopback, established.upstream.port)
        val initial = established.initial
        val owner = active.session.owner
        val client = endpoint()
        fun send(port: Int, destination: SocksDestination = SocksDestination.Ip(loopback)) = raw(
            SocksProtocol.encodeUdpRequest(SocksUdpRequest(destination, port, byteArrayOf(1))))
        fun raw(bytes: ByteArray) = client.send(DatagramPacket(bytes, bytes.size, loopback, relayPort))
        fun response(): ByteArray = receive(client).let {
            checkNotNull(SocksProtocol.decodeUdpRequest(it.data, length = it.length)).payload
        }
        fun time(value: Long) = onOwner { fixture.now.set(value) }
        fun onOwner(action: () -> Unit) = onOwner(owner, action)
        fun await(predicate: (UdpDataPlane.Snapshot) -> Boolean) = this@UdpIdleTimeoutTest.await {
            var result = false
            onOwner { result = predicate(driver.snapshot()) }
            result
        }
        fun assertOpenAfterTimer() {
            val before = owner.stats().firedTimers
            await { owner.stats().firedTimers > before }
            onOwner { assertEquals(SocksSession.State.UDP_ACTIVE, active.session.snapshot().state) }
        }
        fun expectIdle(limit: Long) {
            assertEquals(-1, control.getInputStream().read())
            assertCleaned()
            onOwner {
                val error = active.session.snapshot().closeCause as? UdpIdleTimeout.IdleExpiredException
                assertNotNull(error)
                assertEquals(limit, error!!.idleLimitNanos)
            }
        }
        fun assertCleaned() = onOwner {
            val state = active.session.snapshot()
            assertEquals(SocksSession.State.CLOSED, state.state)
            assertEquals(0, state.bufferBytes)
            assertEquals(0, state.buffers)
            assertNull(state.deadlineNanos)
            assertNull(state.operationId)
            assertFalse(state.hasProtocolLease)
            assertEquals(0L, state.udpCleanupFailures)
            assertEquals(0L, state.operationCleanupFailures)
            assertTrue(driver.snapshot().closed)
            assertEquals(0, driver.snapshot().queuedPackets)
            assertEquals(0, driver.snapshot().queuedBytes)
            assertFalse(active.relay.channel.isOpen)
            assertFalse(active.upstream.channel.isOpen)
            assertEquals(0, owner.stats().timers)
        }
        override fun close() { control.close(); client.close() }
    }

    private fun endpoint() = DatagramSocket(0, loopback).apply { soTimeout = 3000 }
    private fun receive(socket: DatagramSocket) = DatagramPacket(ByteArray(65535), 65535).also(socket::receive)
    private fun onOwner(owner: SocksEventLoop, action: () -> Unit) {
        val done = CountDownLatch(1)
        val failure = AtomicReference<Throwable>()
        assertEquals(SocksEventLoop.Submission.ACCEPTED, owner.submit {
            try { action() } catch (error: Throwable) { failure.set(error) } finally { done.countDown() }
        })
        assertTrue(done.await(3, TimeUnit.SECONDS))
        failure.get()?.let { throw it }
    }
    private fun await(predicate: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (!predicate()) {
            assertTrue("condition deadline", System.nanoTime() < deadline)
            Thread.sleep(2)
        }
    }
}
