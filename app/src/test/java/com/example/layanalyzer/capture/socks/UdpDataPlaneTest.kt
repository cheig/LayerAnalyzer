package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.SocksUdpRequest
import com.example.layanalyzer.capture.UdpDestinationPolicy
import com.example.layanalyzer.capture.UdpVerdict
import java.io.DataInputStream
import java.io.IOException
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
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class UdpDataPlaneTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    @Test fun realEmptyDatagramRoundTripIsAttemptedExactlyOnceWithoutSpin() {
        val sends = AtomicInteger()
        Fixture(io = object : UdpDataPlane.ChannelIo {
            override fun send(channel: DatagramChannel, bytes: ByteBuffer, target: InetSocketAddress): Int {
                sends.incrementAndGet()
                return super.send(channel, bytes, target)
            }
        }).use { f -> f.link().use { link -> endpoint().use { upstream ->
            link.send(upstream.localPort, byteArrayOf())
            val packet = receive(upstream)
            assertEquals(0, packet.length)
            upstream.send(DatagramPacket(byteArrayOf(), 0, packet.address, packet.port))
            assertArrayEquals(byteArrayOf(), link.response())
            f.await { f.runtime.snapshot().queuedPackets == 0 }
            val callbacks = link.owner.stats().readinessCallbacks
            Thread.sleep(50)
            assertEquals(2, sends.get())
            assertTrue(link.owner.stats().readinessCallbacks - callbacks < 4)
            assertEquals(1L, f.runtime.snapshot().ambiguousEmptySends)
            upstream.soTimeout = 80
            assertThrows(SocketTimeoutException::class.java) { receive(upstream) }
            link.onOwner {
                assertEquals(0, link.driver.snapshot().queuedPackets)
                assertEquals(0, link.active.upstream.interestOps() and java.nio.channels.SelectionKey.OP_WRITE)
            }
            assertEquals(0L, f.resolver.stats().lookups)
        } } }
    }

    @Test fun maximumLoopbackResponseAndLargeRequestKeepExactBytes() {
        Fixture().use { f -> f.link().use { link -> endpoint().use { upstream ->
            val bytes = ByteArray(65_497) { (it * 29).toByte() }
            link.send(upstream.localPort, bytes)
            val heard = receive(upstream)
            assertArrayEquals(bytes, heard.data.copyOf(heard.length))
            upstream.send(DatagramPacket(bytes, bytes.size, heard.address, heard.port))
            assertArrayEquals(bytes, link.response())
            f.await { f.runtime.snapshot().queuedBytes == 0 }
            assertTrue(f.runtime.snapshot().peakQueuedBytes >= bytes.size + 10)
        } } }
    }

    @Test fun realIpv6UpstreamUsesSameDatagramDriver() {
        val ipv6 = InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 })
        DatagramSocket(InetSocketAddress(ipv6, 0)).use { upstream ->
            upstream.soTimeout = 3000
            Fixture().use { f -> f.link().use { link ->
                val bytes = byteArrayOf(7, 3, 1)
                link.send(upstream.localPort, bytes, SocksDestination.Ip(ipv6))
                val heard = receive(upstream)
                assertArrayEquals(bytes, heard.data.copyOf(heard.length))
                upstream.send(DatagramPacket(bytes, bytes.size, heard.address, heard.port))
                assertArrayEquals(bytes, link.response())
            } }
        }
    }

    @Test fun emptyWouldBlockAmbiguityDoesNotRetryOrPretendConfirmedSend() {
        val calls = AtomicInteger()
        Fixture(io = object : UdpDataPlane.ChannelIo {
            override fun send(channel: DatagramChannel, bytes: ByteBuffer, target: InetSocketAddress): Int {
                calls.incrementAndGet()
                return 0
            }
        }).use { f -> f.link().use { link ->
            link.send(53, byteArrayOf())
            f.await { f.runtime.snapshot().ambiguousEmptySends == 1L }
            Thread.sleep(25)
            assertEquals(1, calls.get())
            assertEquals(0, f.runtime.snapshot().queuedPackets)
            link.onOwner { assertEquals(0L, link.driver.policy.stats().sentBytes) }
        } }
    }

    @Test fun zeroWriteQueuesWholePacketAndScratchReuseCannotCorruptIt() {
        val blocked = AtomicBoolean(true)
        val attempts = AtomicInteger()
        Fixture(io = blocking(blocked, attempts)).use { f -> f.link().use { link -> endpoint().use { upstream ->
            val first = ByteArray(4096) { (it * 3).toByte() }
            val second = ByteArray(2048) { (it * 5 + 1).toByte() }
            link.send(upstream.localPort, first)
            link.send(upstream.localPort, second)
            link.await { it.queuedPackets == 2 }
            assertEquals(first.size + second.size, f.runtime.snapshot().queuedBytes)
            val before = attempts.get()
            Thread.sleep(30)
            assertTrue("zero write must yield", attempts.get() - before < 100)
            blocked.set(false)
            assertArrayEquals(first, receive(upstream).payload())
            assertArrayEquals(second, receive(upstream).payload())
            link.await { it.queuedPackets == 0 && !it.retryPending }
            assertEquals(0L, f.runtime.snapshot().queueDroppedPackets)
        } } }
    }

    @Test fun partialWriteDropsWholeDatagramAndDoesNotSendItsSuffix() {
        val calls = AtomicInteger()
        Fixture(io = object : UdpDataPlane.ChannelIo {
            override fun send(channel: DatagramChannel, bytes: ByteBuffer, target: InetSocketAddress): Int {
                if (calls.incrementAndGet() == 1) { bytes.position(1); return 1 }
                return super.send(channel, bytes, target)
            }
        }).use { f -> f.link().use { link -> endpoint().use { upstream ->
            link.send(upstream.localPort, byteArrayOf(1, 2, 3))
            link.send(upstream.localPort, byteArrayOf(4, 5))
            assertArrayEquals(byteArrayOf(4, 5), receive(upstream).payload())
            link.await { it.queuedPackets == 0 }
            assertEquals(2, calls.get())
            assertEquals(1L, f.runtime.snapshot().sendFailures)
            link.onOwner { assertEquals(1L, link.driver.policy.stats().sendFailures) }
        } } }
    }

    @Test fun sendExceptionDropsPacketAndAssociationRecovers() {
        val first = AtomicBoolean(true)
        Fixture(io = object : UdpDataPlane.ChannelIo {
            override fun send(channel: DatagramChannel, bytes: ByteBuffer, target: InetSocketAddress): Int {
                if (first.getAndSet(false)) throw IOException("injected send")
                return super.send(channel, bytes, target)
            }
        }).use { f -> f.link().use { link -> endpoint().use { upstream ->
            link.send(upstream.localPort, byteArrayOf(1))
            link.send(upstream.localPort, byteArrayOf(2))
            assertArrayEquals(byteArrayOf(2), receive(upstream).payload())
            assertEquals(1L, f.runtime.snapshot().sendFailures)
        } } }
    }

    @Test fun receiveExceptionClosesScopeAndReturnsBudget() {
        Fixture(io = object : UdpDataPlane.ChannelIo {
            override fun receive(channel: DatagramChannel, scratch: ByteBuffer): InetSocketAddress? = throw IOException("receive")
        }, expectedCallbackFailures = 1).use { f -> f.link().use { link ->
            link.send(53, byteArrayOf(1))
            assertEquals(-1, link.control.getInputStream().read())
            f.await { f.runtime.snapshot().associations == 0 }
        } }
    }

    @Test fun eightPacketLimitDropsNewestAndKeepsBothDirectionsInOneFifo() {
        val blocked = AtomicBoolean(false)
        Fixture(io = blocking(blocked)).use { f -> f.link().use { link -> endpoint().use { upstream ->
            link.send(upstream.localPort, byteArrayOf(99))
            val initial = receive(upstream)
            blocked.set(true)
            repeat(7) { link.send(upstream.localPort, byteArrayOf(it.toByte())) }
            link.await { it.queuedPackets == 7 }
            upstream.send(DatagramPacket(byteArrayOf(42), 1, initial.address, initial.port))
            link.await { it.queuedPackets == 8 }
            link.send(upstream.localPort, byteArrayOf(100))
            link.await { it.policy.queueDroppedDatagrams == 1L }
            assertEquals(18, f.runtime.snapshot().queuedBytes) // 7 payload bytes + 11-byte encoded response
            assertEquals(1L, f.runtime.snapshot().queueDroppedPackets)
            blocked.set(false)
            repeat(7) { assertArrayEquals(byteArrayOf(it.toByte()), receive(upstream).payload()) }
            assertArrayEquals(byteArrayOf(42), link.response())
            link.await { it.queuedPackets == 0 }
            link.send(upstream.localPort, byteArrayOf(101))
            assertArrayEquals(byteArrayOf(101), receive(upstream).payload())
        } } }
    }

    @Test fun associationByteLimitCountsEncodedResponseHeaderAndRecovers() {
        val blocked = AtomicBoolean(false)
        val limits = UdpDataPlaneRuntime.Limits(bytesPerAssociation = 20)
        Fixture(limits, io = blocking(blocked)).use { f -> f.link().use { link -> endpoint().use { upstream ->
            link.send(upstream.localPort, byteArrayOf(1))
            val sent = receive(upstream)
            blocked.set(true)
            link.send(upstream.localPort, ByteArray(10) { 2 })
            link.await { it.queuedBytes == 10 }
            upstream.send(DatagramPacket(byteArrayOf(3), 1, sent.address, sent.port))
            link.await { it.policy.queueDroppedDatagrams == 1L }
            assertEquals(11L, f.runtime.snapshot().queueDroppedBytes)
            assertEquals(10, f.runtime.snapshot().queuedBytes)
            blocked.set(false)
            assertEquals(10, receive(upstream).length)
            link.await { it.queuedPackets == 0 }
            upstream.send(DatagramPacket(byteArrayOf(4), 1, sent.address, sent.port))
            assertArrayEquals(byteArrayOf(4), link.response())
        } } }
    }

    @Test fun default128KiBAssociationLimitRetainsLargePackets() {
        val blocked = AtomicBoolean(true)
        Fixture(io = blocking(blocked)).use { f -> f.link().use { link -> endpoint().use { upstream ->
            val large = ByteArray(60_000) { 7 }
            repeat(2) { index ->
                link.send(upstream.localPort, large)
                link.await { it.queuedPackets == index + 1 }
            }
            link.send(upstream.localPort, large)
            link.await { it.policy.queueDroppedDatagrams == 1L }
            assertEquals(120_000, f.runtime.snapshot().queuedBytes)
            blocked.set(false)
            repeat(2) { assertArrayEquals(large, receive(upstream).payload()) }
            link.await { it.queuedBytes == 0 }
        } } }
    }

    @Test fun globalBudgetIsSharedAcrossOwnersAndRecovers() {
        val blocked = AtomicBoolean(true)
        Fixture(UdpDataPlaneRuntime.Limits(globalBytes = 100_000), io = blocking(blocked)).use { f ->
            f.link().use { first -> f.link().use { second -> endpoint().use { upstream ->
                assertNotSame(first.owner, second.owner)
                first.send(upstream.localPort, ByteArray(60_000) { 1 })
                first.await { it.queuedPackets == 1 }
                second.send(upstream.localPort, ByteArray(60_000) { 2 })
                second.await { it.policy.queueDroppedDatagrams == 1L }
                assertEquals(60_000, f.runtime.snapshot().queuedBytes)
                blocked.set(false)
                assertEquals(1.toByte(), receive(upstream).data[0])
                first.await { it.queuedPackets == 0 }
                second.send(upstream.localPort, ByteArray(60_000) { 3 })
                assertEquals(3.toByte(), receive(upstream).data[0])
                second.await { it.queuedPackets == 0 }
                assertEquals(0, f.runtime.snapshot().queuedBytes)
            } } }
        }
    }

    @Test fun production8MiBGlobalBudgetIsExactIncludingZeroLengthPacketSlots() {
        val runtime = UdpDataPlaneRuntime()
        SocksEventLoopGroup().use { group ->
            group.start()
            val leases = ArrayList<Pair<SocksEventLoop, UdpDataPlaneRuntime.Lease>>()
            repeat(64) { index ->
                val loop = group.loop(index % 2)
                onOwner(loop) {
                    val lease = runtime.acquire(loop)!!
                    leases.add(loop to lease)
                    repeat(8) { assertTrue(lease.reserve(16 * 1024)) }
                }
            }
            assertEquals(8 * 1024 * 1024, runtime.snapshot().queuedBytes)
            assertEquals(512, runtime.snapshot().queuedPackets)
            assertEquals(2, runtime.snapshot().scratchBuffers)
            onOwner(group.loop(0)) {
                val extra = runtime.acquire(group.loop(0))!!
                assertFalse(extra.reserve(1))
                repeat(8) { assertTrue(extra.reserve(0)) }
                assertFalse(extra.reserve(0))
                extra.close()
            }
            val (owner, first) = leases.first()
            onOwner(owner) { first.release(16 * 1024); assertTrue(first.reserve(16 * 1024)) }
            leases.forEach { (loop, lease) -> onOwner(loop) { lease.close(); lease.close() } }
            assertEquals(0, runtime.snapshot().queuedBytes)
            assertEquals(0, runtime.snapshot().queuedPackets)
            assertEquals(0, runtime.snapshot().scratchBuffers)
            assertEquals(0, runtime.snapshot().associations)
        }
    }

    @Test fun allAssociationsOnSameOwnerUseOneScratchAndStopReleasesIt() {
        val buffers = java.util.Collections.synchronizedMap(LinkedHashMap<Thread, MutableSet<ByteBuffer>>())
        Fixture(io = object : UdpDataPlane.ChannelIo {
            override fun receive(channel: DatagramChannel, scratch: ByteBuffer): InetSocketAddress? {
                synchronized(buffers) {
                    buffers.getOrPut(Thread.currentThread()) {
                        java.util.Collections.newSetFromMap(java.util.IdentityHashMap())
                    }.add(scratch)
                }
                return super.receive(channel, scratch)
            }
        }).use { f ->
            val links = List(6) { f.link() }
            try {
                endpoint().use { upstream ->
                    links.forEachIndexed { index, link -> link.send(upstream.localPort, byteArrayOf(index.toByte())) }
                    repeat(6) { receive(upstream) }
                    f.await { f.runtime.snapshot().queuedPackets == 0 }
                    assertEquals(2, buffers.size)
                    assertTrue(buffers.values.all { it.size == 1 })
                    assertEquals(2 * 65535, f.runtime.snapshot().scratchBytes)
                    assertEquals(2, f.threads.get())
                }
            } finally { links.forEach { it.close() } }
        }
    }

    @Test fun dnsPacketPrecedesLaterLiteralAndResolvesOnlyOnWorker() {
        val release = CountDownLatch(1)
        val entered = CountDownLatch(1)
        Fixture(lookup = {
            assertTrue(Thread.currentThread().name.startsWith("SocksDns-"))
            entered.countDown(); assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback)
        }).use { f -> f.link().use { link -> endpoint().use { upstream ->
            try {
                link.send(upstream.localPort, byteArrayOf(1), SocksDestination.Domain("ordering.test"))
                assertTrue(entered.await(3, TimeUnit.SECONDS))
                link.send(upstream.localPort, byteArrayOf(2))
                link.await { it.queuedPackets == 2 && it.resolving }
                upstream.soTimeout = 80
                assertThrows(SocketTimeoutException::class.java) { receive(upstream) }
                release.countDown()
                upstream.soTimeout = 3000
                assertArrayEquals(byteArrayOf(1), receive(upstream).payload())
                assertArrayEquals(byteArrayOf(2), receive(upstream).payload())
                link.await { it.queuedPackets == 0 && !it.resolving }
                assertEquals(1L, f.resolver.stats().lookups)
            } finally { release.countDown() }
        } } }
    }

    @Test fun concurrentAssociationsMergeDnsWithoutMergingTheirPayloads() {
        val release = CountDownLatch(1)
        Fixture(lookup = { assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback) }).use { f ->
            f.link().use { first -> f.link().use { second -> endpoint().use { upstream ->
                try {
                    first.send(upstream.localPort, byteArrayOf(1), SocksDestination.Domain("MERGE.test"))
                    second.send(upstream.localPort, byteArrayOf(2), SocksDestination.Domain("merge.test"))
                    f.await { f.resolver.stats().merged == 1L }
                    assertEquals(2, f.runtime.snapshot().queuedPackets)
                    release.countDown()
                    assertEquals(setOf(1.toByte(), 2.toByte()), setOf(receive(upstream).data[0], receive(upstream).data[0]))
                    f.await { f.runtime.snapshot().queuedPackets == 0 }
                    assertEquals(1L, f.resolver.stats().lookups)
                } finally { release.countDown() }
            } } }
        }
    }

    @Test fun unresolvedPacketsShareEightSlotsAndOnlyHeadStartsDns() {
        val release = CountDownLatch(1)
        Fixture(lookup = { assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback) }).use { f ->
            f.link().use { link -> endpoint().use { upstream ->
                try {
                    repeat(9) { index ->
                        link.send(upstream.localPort, byteArrayOf(index.toByte()), SocksDestination.Domain("$index.fifo.test"))
                    }
                    link.await { it.queuedPackets == 8 && it.policy.queueDroppedDatagrams == 1L }
                    f.await { f.resolver.stats().activeLookups == 1 }
                    assertEquals(8, f.runtime.snapshot().queuedBytes)
                    assertEquals(1, f.resolver.stats().subscribers)
                    assertEquals(0, f.resolver.stats().queuedQueries)
                    assertEquals(1L, f.resolver.stats().lookups)
                    release.countDown()
                    repeat(8) { index -> assertArrayEquals(byteArrayOf(index.toByte()), receive(upstream).payload()) }
                    link.await { it.queuedPackets == 0 && !it.resolving }
                    assertEquals(8L, f.resolver.stats().lookups)
                } finally { release.countDown() }
            } }
        }
    }

    @Test fun resolvedPolicyDropReleasesHeadAndPreservesFollowingPacket() {
        val release = CountDownLatch(1)
        val rule = UdpDestinationPolicy { _, port ->
            if (port == 443) UdpVerdict.BlockSelectedUdp443 else UdpVerdict.Forward
        }
        Fixture(rule = rule, lookup = {
            assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback)
        }).use { f -> f.link().use { link -> endpoint().use { upstream ->
            try {
                link.send(443, ByteArray(4096), SocksDestination.Domain("blocked.test"))
                link.send(upstream.localPort, byteArrayOf(3))
                link.await { it.queuedPackets == 2 }
                release.countDown()
                assertArrayEquals(byteArrayOf(3), receive(upstream).payload())
                link.await { it.queuedBytes == 0 && it.policy.intervention.blockedDatagrams == 1L }
                link.onOwner {
                    assertEquals(1, link.driver.policy.stats().allowedPeers)
                    assertEquals(0L, link.driver.policy.stats().sendFailures)
                    assertEquals(0L, link.driver.policy.stats().queueDroppedDatagrams)
                }
                assertEquals(0L, f.runtime.snapshot().queueDroppedPackets)
            } finally { release.countDown() }
        } } }
    }

    @Test fun resolverQueueFullDropsOnlyFailedHeadCancelsOperationAndKeepsUdpActive() {
        val release = CountDownLatch(1)
        Fixture(resolverLimits = SocksResolver.Limits(workers = 1, queuedQueries = 1), lookup = {
            assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback)
        }).use { f ->
            f.link().use { first -> f.link().use { second -> f.link().use { third -> endpoint().use { upstream ->
                try {
                    first.send(53, byteArrayOf(1), SocksDestination.Domain("first.test"))
                    f.await { f.resolver.stats().activeLookups == 1 }
                    second.send(53, byteArrayOf(2), SocksDestination.Domain("second.test"))
                    f.await { f.resolver.stats().queuedQueries == 1 }
                    third.send(53, byteArrayOf(3), SocksDestination.Domain("third.test"))
                    third.await { it.policy.resolutionFailures == 1L }
                    third.onOwner {
                        assertNull(third.active.session.snapshot().operationId)
                        assertEquals(SocksSession.State.UDP_ACTIVE, third.active.session.snapshot().state)
                    }
                    third.send(upstream.localPort, byteArrayOf(4))
                    assertArrayEquals(byteArrayOf(4), receive(upstream).payload())
                } finally { release.countDown() }
            } } } }
        }
    }

    @Test fun dnsTimeoutFreesPacketAndLateResultCannotOvertakeNextPacket() {
        val release = CountDownLatch(1)
        Fixture(dnsTimeoutNanos = 80_000_000, lookup = {
            assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback)
        }).use { f -> f.link().use { link -> endpoint().use { upstream ->
            try {
                link.send(upstream.localPort, byteArrayOf(1), SocksDestination.Domain("late.test"))
                f.await { f.resolver.stats().activeLookups == 1 }
                link.send(upstream.localPort, byteArrayOf(2))
                assertArrayEquals(byteArrayOf(2), receive(upstream).payload())
                link.await { it.queuedPackets == 0 && it.policy.resolutionFailures == 1L }
                assertEquals(1L, f.resolver.stats().timedOut)
                release.countDown()
                f.await { f.resolver.stats().activeLookups == 0 }
                upstream.soTimeout = 80
                assertThrows(SocketTimeoutException::class.java) { receive(upstream) }
            } finally { release.countDown() }
        } } }
    }

    @Test fun dnsFailureDoesNotRenewActivityAndNextLiteralStillForwards() {
        Fixture(lookup = { throw IOException("DNS fixture") }).use { f -> f.link().use { link -> endpoint().use { upstream ->
            link.send(upstream.localPort, byteArrayOf(1), SocksDestination.Domain("failed.test"))
            link.await { it.policy.resolutionFailures == 1L && it.queuedPackets == 0 }
            link.send(upstream.localPort, byteArrayOf(2))
            assertArrayEquals(byteArrayOf(2), receive(upstream).payload())
            link.onOwner { assertNull(link.active.session.snapshot().operationId) }
        } } }
    }

    @Test fun completionIngressRejectionRemainsBoundedUntilTimeoutAndRecovers() {
        val release = CountDownLatch(1)
        val ownerHeld = CountDownLatch(1)
        val ownerRelease = CountDownLatch(1)
        Fixture(config = SocksEventLoopConfig(completionCapacity = 1, completionsPerTurn = 1),
            dnsTimeoutNanos = 150_000_000,
            lookup = { assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback) }).use { f ->
            f.link().use { link -> endpoint().use { upstream ->
                try {
                    link.send(upstream.localPort, byteArrayOf(1), SocksDestination.Domain("rejected.test"))
                    f.await { f.resolver.stats().activeLookups == 1 }
                    assertEquals(SocksEventLoop.Submission.ACCEPTED, link.owner.submit {
                        ownerHeld.countDown(); assertTrue(ownerRelease.await(3, TimeUnit.SECONDS))
                    })
                    assertTrue(ownerHeld.await(3, TimeUnit.SECONDS))
                    assertEquals(SocksEventLoop.Submission.ACCEPTED, link.owner.complete {})
                    release.countDown()
                    f.await { f.resolver.stats().rejectedCompletions == 1L }
                    assertEquals(1, f.runtime.snapshot().queuedPackets)
                    ownerRelease.countDown()
                    link.await { it.policy.resolutionFailures == 1L && it.queuedPackets == 0 }
                    link.send(upstream.localPort, byteArrayOf(2))
                    assertArrayEquals(byteArrayOf(2), receive(upstream).payload())
                } finally { release.countDown(); ownerRelease.countDown() }
            } }
        }
    }

    @Test fun controlEofWithPendingDnsReleasesEverythingBeforeLateWorkerReturns() {
        val release = CountDownLatch(1)
        Fixture(lookup = { assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback) }).use { f ->
            try {
                f.link().use { link ->
                    link.send(53, ByteArray(100), SocksDestination.Domain("closed.test"))
                    f.await { f.resolver.stats().activeLookups == 1 }
                    link.send(53, ByteArray(200))
                    link.await { it.queuedPackets == 2 }
                    link.control.shutdownOutput()
                    assertEquals(-1, link.control.getInputStream().read())
                    f.await { f.runtime.snapshot().associations == 0 && f.resolver.stats().subscribers == 0 }
                    assertEquals(0, f.runtime.snapshot().queuedBytes)
                    assertEquals(0, f.runtime.snapshot().scratchBuffers)
                    release.countDown()
                    f.await { f.resolver.stats().activeLookups == 0 }
                    link.onOwner { assertTrue(link.driver.snapshot().closed) }
                }
            } finally { release.countDown() }
        }
    }

    @Test fun stopReleasesDnsAndQueuedSendsWithoutWaitingForBlockedLookup() {
        val release = CountDownLatch(1)
        Fixture(io = blocking(AtomicBoolean(true)), lookup = {
            assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback)
        }).use { f ->
            f.link().use { resolving -> f.link().use { sending ->
                try {
                    resolving.send(53, ByteArray(4096), SocksDestination.Domain("stopped.test"))
                    f.await { f.resolver.stats().activeLookups == 1 }
                    sending.send(53, ByteArray(2048))
                    sending.await { it.queuedPackets == 1 }
                    assertTrue(f.server.stop())
                    assertEquals(1, f.resolver.stats().activeLookups)
                    assertEquals(0, f.resolver.stats().subscribers)
                    assertEquals(0, f.runtime.snapshot().queuedPackets)
                    assertEquals(0, f.runtime.snapshot().scratchBuffers)
                    assertEquals(0, f.server.stats().loops.sumOf { it.timers })
                    assertEquals(-1, resolving.control.getInputStream().read())
                    assertEquals(-1, sending.control.getInputStream().read())
                    release.countDown()
                    f.await { f.resolver.stats().activeLookups == 0 }
                    assertEquals(1L, f.resolver.stats().abandonedResults)
                } finally { release.countDown() }
            } }
        }
    }

    @Test fun networkScopeInvalidationClosesOnNextIoAndLateDnsCannotSend() {
        val release = CountDownLatch(1)
        Fixture(lookup = { assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback) }).use { f ->
            f.link().use { link -> endpoint().use { upstream ->
                try {
                    link.send(upstream.localPort, ByteArray(100), SocksDestination.Domain("network.test"))
                    f.await { f.resolver.stats().activeLookups == 1 }
                    f.scope.close()
                    link.send(upstream.localPort, byteArrayOf(2))
                    assertEquals(-1, link.control.getInputStream().read())
                    f.await { f.runtime.snapshot().associations == 0 }
                    release.countDown()
                    f.await { f.resolver.stats().activeLookups == 0 }
                    upstream.soTimeout = 80
                    assertThrows(SocketTimeoutException::class.java) { receive(upstream) }
                    assertEquals(0, f.runtime.snapshot().queuedBytes)
                } finally { release.countDown() }
            } }
        }
    }

    @Test fun retryTimerRejectionClosesAssociationAndFreesWholeQueue() {
        Fixture(config = SocksEventLoopConfig(timerCapacity = 1, timersPerTurn = 1),
            io = blocking(AtomicBoolean(true))).use { f -> f.link().use { link ->
            link.onOwner {
                assertEquals(SocksEventLoop.Submission.ACCEPTED,
                    link.owner.schedule(TimeUnit.SECONDS.toNanos(30), link.active.session.resource) {}.result)
            }
            link.send(53, ByteArray(500))
            assertEquals(-1, link.control.getInputStream().read())
            f.await { f.runtime.snapshot().associations == 0 }
            assertEquals(0, f.runtime.snapshot().queuedBytes)
            link.onOwner {
                assertTrue(link.driver.snapshot().closed)
                assertEquals(0, link.owner.stats().timers)
            }
        } }
    }

    @Test fun ownerExpiryHookRunsBeforeReceiveAndDnsCompletionAndCleansOnce() {
        val release = CountDownLatch(1)
        val expired = AtomicBoolean(false)
        val cleaned = AtomicInteger()
        Fixture(lookup = { assertTrue(release.await(3, TimeUnit.SECONDS)); arrayOf(loopback) }).use { f ->
            f.link().use { link ->
                try {
                    link.onOwner { link.driver.installLifecycle(object : UdpDataPlane.Lifecycle {
                        override fun beforeIo(nowNanos: Long): Boolean {
                            if (expired.get()) link.active.close()
                            return !expired.get()
                        }
                        override fun close() { cleaned.incrementAndGet() }
                    }) }
                    link.send(53, byteArrayOf(1), SocksDestination.Domain("expiry.test"))
                    f.await { f.resolver.stats().activeLookups == 1 }
                    expired.set(true)
                    release.countDown()
                    assertEquals(-1, link.control.getInputStream().read())
                    f.await { f.runtime.snapshot().associations == 0 }
                    assertEquals(1, cleaned.get())
                } finally { release.countDown() }
            }
        }
    }

    @Test fun hotAssociationYieldsWithin32DatagramsAndOtherOwnerStillMakesProgress() {
        val synthesize = AtomicBoolean(true)
        val reads = AtomicInteger()
        Fixture(io = object : UdpDataPlane.ChannelIo {
            override fun receive(channel: DatagramChannel, scratch: ByteBuffer): InetSocketAddress? {
                if (synthesize.get()) {
                    reads.incrementAndGet()
                    scratch.put(0) // invalid packet, continuous ready source without network buffer losses
                    return InetSocketAddress(loopback, 12345)
                }
                return super.receive(channel, scratch)
            }
        }).use { f -> f.link().use { hot -> f.link().use { other ->
            hot.send(53, byteArrayOf(1))
            f.await { reads.get() >= 64 }
            other.onOwner { assertEquals(SocksSession.State.UDP_ACTIVE, other.active.session.snapshot().state) }
            hot.onOwner { assertTrue(hot.driver.policy.stats().invalidDatagrams >= 32) }
            assertEquals(32, f.runtime.snapshot().maxDatagramsPerCallback)
            synthesize.set(false)
            assertEquals(2, f.threads.get())
        } } }
    }

    @Test fun runStopMarksScratchUntilOwnerFinishesCurrentReceive() {
        val inside = CountDownLatch(1)
        val release = CountDownLatch(1)
        Fixture(io = object : UdpDataPlane.ChannelIo {
            override fun receive(channel: DatagramChannel, scratch: ByteBuffer): InetSocketAddress? {
                val result = super.receive(channel, scratch)
                if (result != null) {
                    val first = scratch.array()[0]
                    inside.countDown()
                    assertTrue(release.await(3, TimeUnit.SECONDS))
                    assertEquals(first, scratch.array()[0])
                }
                return result
            }
        }).use { f -> f.link().use { link ->
            try {
                link.send(53, byteArrayOf(1))
                assertTrue(inside.await(3, TimeUnit.SECONDS))
                f.runtime.close()
                assertEquals(1, f.runtime.snapshot().scratchBuffers)
                release.countDown()
                assertEquals(-1, link.control.getInputStream().read())
                f.await { f.runtime.snapshot().scratchBuffers == 0 }
            } finally { release.countDown() }
        } }
    }

    private inner class Fixture(
        limits: UdpDataPlaneRuntime.Limits = UdpDataPlaneRuntime.Limits(),
        io: UdpDataPlane.ChannelIo = UdpDataPlane.ChannelIo.CHANNEL,
        config: SocksEventLoopConfig = SocksEventLoopConfig(),
        resolverLimits: SocksResolver.Limits = SocksResolver.Limits(),
        dnsTimeoutNanos: Long = SocksNioTcpResolve.DNS_TIMEOUT_NANOS,
        rule: UdpDestinationPolicy = UdpDestinationPolicy.PRESERVE,
        lookup: (String) -> Array<InetAddress> = { arrayOf(loopback) },
        val expectedCallbackFailures: Long = 0
    ) : AutoCloseable {
        val runtime = UdpDataPlaneRuntime(limits)
        val resolver = SocksResolver.forTest(resolverLimits)
        lateinit var scope: SocksResolver.Scope
        val threads = AtomicInteger()
        val established = LinkedBlockingQueue<Pair<UdpAssociation.Active, UdpDataPlane>>()
        val association = UdpAssociation({}, { active ->
            established.add(active to UdpDataPlane(active, runtime, scope, rule, io, dnsTimeoutNanos))
        })
        val server = SocksNioServer(SocksNioHandshake({ SocksCredentials.of("u", "p") }, association::start),
            config = config,
            threadFactory = { task, name -> threads.incrementAndGet(); Thread(task, name) },
            onRunStarting = { generation -> scope = resolver.newScope(generation, 1, lookup) },
            onRunStopping = { runtime.close(); scope.close() }).also { it.start() }

        fun link(): Link {
            val control = Socket(loopback, server.stats().port!!)
            control.soTimeout = 3000
            control.getOutputStream().write(byteArrayOf(5, 1, 2, 1, 1, 'u'.code.toByte(), 1, 'p'.code.toByte()) +
                SocksProtocol.encodeRequest(SocksRequest(3, SocksDestination.Ip(loopback), 0)))
            val reply = ByteArray(14)
            DataInputStream(control.getInputStream()).readFully(reply)
            assertArrayEquals(byteArrayOf(5, 2, 1, 0, 5, 0, 0, 1), reply.copyOf(8))
            val (active, driver) = checkNotNull(established.poll(3, TimeUnit.SECONDS))
            return Link(control, active, driver)
        }

        fun await(predicate: () -> Boolean) = awaitCondition(predicate)

        override fun close() {
            assertTrue(server.stop())
            assertTrue(resolver.shutdownForTest())
            val stats = runtime.snapshot()
            assertEquals(0, stats.associations)
            assertEquals(0, stats.queuedPackets)
            assertEquals(0, stats.queuedBytes)
            assertEquals(0, stats.scratchBuffers)
            assertEquals(0, scope.stats().subscribers)
            assertEquals(0, server.stats().admission!!.udp.current)
            assertEquals(expectedCallbackFailures, server.stats().loops.sumOf { it.callbackFailures })
            server.stats().loops.forEach { loop ->
                assertEquals(0, loop.channels)
                assertEquals(0, loop.keys)
                assertEquals(0, loop.resources)
                assertEquals(0, loop.timers)
                assertEquals(0, loop.commands)
                assertEquals(0, loop.completions)
                assertEquals(0L, loop.cleanupFailures)
            }
        }
    }

    private inner class Link(val control: Socket, val active: UdpAssociation.Active, val driver: UdpDataPlane) : AutoCloseable {
        val owner = active.session.owner
        val client = endpoint()
        val relayPort = ((active.relay.channel as DatagramChannel).localAddress as InetSocketAddress).port
        fun send(port: Int, bytes: ByteArray, destination: SocksDestination = SocksDestination.Ip(loopback)) {
            val frame = SocksProtocol.encodeUdpRequest(SocksUdpRequest(destination, port, bytes))
            client.send(DatagramPacket(frame, frame.size, loopback, relayPort))
        }
        fun response(): ByteArray {
            val packet = receive(client)
            return checkNotNull(SocksProtocol.decodeUdpRequest(packet.data, length = packet.length)).payload
        }
        fun onOwner(action: () -> Unit) = onOwner(owner, action)
        fun await(predicate: (UdpDataPlane.Snapshot) -> Boolean) = awaitCondition {
            var matches = false
            onOwner { matches = predicate(driver.snapshot()) }
            matches
        }
        override fun close() { control.close(); client.close() }
    }

    private fun blocking(flag: AtomicBoolean, attempts: AtomicInteger = AtomicInteger()) = object : UdpDataPlane.ChannelIo {
        override fun send(channel: DatagramChannel, bytes: ByteBuffer, target: InetSocketAddress): Int {
            attempts.incrementAndGet()
            return if (flag.get()) 0 else super.send(channel, bytes, target)
        }
    }
    private fun endpoint() = DatagramSocket(0, loopback).apply { soTimeout = 3000; receiveBufferSize = 1024 * 1024 }
    private fun receive(socket: DatagramSocket) = DatagramPacket(ByteArray(65535), 65535).also(socket::receive)
    private fun DatagramPacket.payload() = data.copyOf(length)
    private fun onOwner(owner: SocksEventLoop, action: () -> Unit) {
        val finished = CountDownLatch(1)
        val error = AtomicReference<Throwable>()
        assertEquals(SocksEventLoop.Submission.ACCEPTED, owner.submit {
            try { action() } catch (cause: Throwable) { error.set(cause) } finally { finished.countDown() }
        })
        assertTrue(finished.await(3, TimeUnit.SECONDS))
        error.get()?.let { throw it }
    }
    private fun awaitCondition(predicate: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (!predicate()) {
            assertTrue("condition deadline", System.nanoTime() < deadline)
            Thread.sleep(2)
        }
    }
}
