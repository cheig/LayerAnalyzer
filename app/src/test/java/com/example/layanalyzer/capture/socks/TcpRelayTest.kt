// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class TcpRelayTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val credentials = SocksCredentials.of("User", "Password")
    private val handshake = byteArrayOf(5, 1, 2, 1, 4) + "User".toByteArray() + byteArrayOf(8) + "Password".toByteArray()

    @Test fun bufferBoundsAlwaysFitRetainedHandshakeInputAndNeverExceed16KiB() {
        assertThrows(IllegalArgumentException::class.java) { SocksTcpBufferBudget(directionBytes = 1023) }
        assertThrows(IllegalArgumentException::class.java) { SocksTcpBufferBudget(directionBytes = 16 * 1024 + 1) }
        assertThrows(IllegalArgumentException::class.java) { SocksTcpBufferBudget(capacityBytes = 2047, directionBytes = 1024) }
    }

    @Test fun smallestBufferPreservesWholeRetainedSuffixBeforeReadiness() = target { target ->
        Fixture(budget = SocksTcpBufferBudget(capacityBytes = 2048, directionBytes = 1024)).use { f ->
            val body = payload(1000, 23)
            f.client(target.localPort, body).use { client -> target.accept().use { remote ->
                reply(client); f.entry(); assertArrayEquals(body, read(remote, body.size))
                assertTrue(f.budget.snapshot().peakAllocatedBytes <= 2048)
            } }
        }
    }

    @Test fun bidirectionalLargeTransferPreservesEveryByteAcrossBoundedTurns() = target { target ->
        Fixture().use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry()
            val upload = payload(512 * 1024, 7); val download = payload(512 * 1024, 19)
            val workers = Executors.newFixedThreadPool(4)
            try {
                val sent = workers.submit { client.getOutputStream().write(upload) }
                val returned = workers.submit { remote.getOutputStream().write(download) }
                val received = workers.submit<ByteArray> { read(remote, upload.size) }
                val response = workers.submit<ByteArray> { read(client, download.size) }
                assertArrayEquals(upload, received.get(10, TimeUnit.SECONDS))
                assertArrayEquals(download, response.get(10, TimeUnit.SECONDS))
                sent.get(10, TimeUnit.SECONDS); returned.get(10, TimeUnit.SECONDS)
                f.owner(entry) {
                    val snapshot = entry.handle.snapshot()
                    assertEquals(upload.size.toLong(), snapshot.clientToUpstream.writtenBytes)
                    assertEquals(download.size.toLong(), snapshot.upstreamToClient.writtenBytes)
                    assertTrue(snapshot.maxBytesPerCallback <= 32 * 1024)
                    assertTrue(snapshot.callbacks > 32)
                    assertEquals(32 * 1024, entry.client.session.snapshot().bufferBytes)
                    assertEquals(SocksSession.State.TCP_RELAY, entry.client.session.snapshot().state)
                }
            } finally { workers.shutdownNow(); assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS)) }
        } } }
    }

    @Test fun retainedHandshakePayloadMovesWithoutAnotherClientWrite() = target { target ->
        Fixture().use { f ->
            val body = payload(700, 31)
            f.client(target.localPort, body).use { client -> target.accept().use { remote ->
                reply(client); val entry = f.entry()
                assertArrayEquals(body, read(remote, body.size))
                f.owner(entry) {
                    assertEquals(0, entry.client.bufferedClientBytes)
                    assertEquals(16 * 1024, entry.client.session.snapshot().bufferBytes)
                }
            } }
        }
    }

    @Test fun shortReadsAndWritesPreserveBothDirectionsAndReplyOrder() = target { target ->
        val clientIo = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) = limited(target, 29) { channel.read(it) }
            override fun write(channel: SocketChannel, source: ByteBuffer) = limited(source, 3) { channel.write(it) }
        }
        val upstreamIo = object : TcpRelay.UpstreamIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) = limited(target, 31) { channel.read(it) }
            override fun write(channel: SocketChannel, source: ByteBuffer) = limited(source, 7) { channel.write(it) }
        }
        Fixture(clientIo = clientIo, io = upstreamIo).use { f ->
            val body = payload(8192, 47)
            f.client(target.localPort, body).use { client -> target.accept().use { remote ->
                remote.getOutputStream().write(body) // arrives while the 3-byte SOCKS reply is draining
                reply(client)
                assertArrayEquals(body, read(client, body.size))
                assertArrayEquals(body, read(remote, body.size))
                assertNoData(client)
            } }
        }
    }

    @Test fun zeroUpstreamWritePausesAtHighWaterResumesAtLowWaterAndKeepsSuffix() = target { target ->
        val permits = AtomicInteger()
        val blocked = CountDownLatch(1)
        val io = object : TcpRelay.UpstreamIo {
            override fun write(channel: SocketChannel, source: ByteBuffer): Int {
                if (permits.getAndUpdate { maxOf(0, it - 1) } <= 0) { blocked.countDown(); return 0 }
                return limited(source, 4096) { channel.write(it) }
            }
        }
        Fixture(io = io).use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); val body = payload(32 * 1024, 59)
            client.getOutputStream().write(body)
            assertTrue(blocked.await(3, TimeUnit.SECONDS))
            await { f.inspect(entry).clientToUpstream.readPaused }
            assertEquals(16 * 1024, f.inspect(entry).clientToUpstream.queuedBytes)
            permits.set(1)
            assertArrayEquals(body.copyOfRange(0, 4096), read(remote, 4096))
            await { f.inspect(entry).clientToUpstream.queuedBytes == 12 * 1024 }
            assertTrue(f.inspect(entry).clientToUpstream.readPaused) // above low water: no refill
            permits.set(1)
            assertArrayEquals(body.copyOfRange(4096, 8192), read(remote, 4096))
            await { f.inspect(entry).clientToUpstream.readBytes > 16 * 1024 } // <=8KiB enabled reads
            permits.set(100)
            assertArrayEquals(body.copyOfRange(8192, body.size), read(remote, body.size - 8192))
            await { f.inspect(entry).clientToUpstream.queuedBytes == 0 }
            f.owner(entry) { assertEquals(SelectionKey.OP_READ, entry.upstream.interestOps()) }
            assertTrue(f.budget.snapshot().peakAllocatedBytes <= 32 * 1024)
        } } }
    }

    @Test fun zeroClientWriteDoesNotDropDownstreamDataOrBusySpin() = target { target ->
        val relayPhase = AtomicBoolean(); val allow = AtomicBoolean(); val calls = AtomicInteger()
        val clientIo = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
            override fun write(channel: SocketChannel, source: ByteBuffer): Int {
                if (relayPhase.get() && !allow.get()) { calls.incrementAndGet(); return 0 }
                return limited(source, 127) { channel.write(it) }
            }
        }
        Fixture(clientIo = clientIo).use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); relayPhase.set(true)
            val body = payload(64 * 1024, 71); remote.getOutputStream().write(body)
            await { f.inspect(entry).upstreamToClient.readPaused }
            val before = calls.get(); assertNoData(client)
            assertTrue("zero-write must yield to a timer", calls.get() - before < 200)
            allow.set(true); assertArrayEquals(body, read(client, body.size))
            assertTrue(f.inspect(entry).upstreamToClient.zeroWrites > 0)
        } } }
    }

    @Test fun zeroReadYieldsAndLaterReadinessRecovers() = target { target ->
        val allow = AtomicBoolean(); val calls = AtomicInteger()
        val io = object : TcpRelay.UpstreamIo {
            override fun read(channel: SocketChannel, target: ByteBuffer): Int {
                if (!allow.get()) { calls.incrementAndGet(); return 0 }
                return channel.read(target)
            }
        }
        Fixture(io = io).use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); remote.getOutputStream().write(byteArrayOf(43))
            await { calls.get() > 0 }; val before = calls.get(); assertNoData(client)
            assertTrue(calls.get() - before < 200)
            allow.set(true); assertArrayEquals(byteArrayOf(43), read(client, 1))
            assertTrue(f.inspect(entry).upstreamToClient.zeroReads > 0)
        } } }
    }

    @Test fun idleConnectionsHaveNoDataAllocationNoWriteInterestAndNoReadinessSpin() = target { target ->
        Fixture().use { f -> f.client(target.localPort).use { client -> target.accept().use {
            reply(client); val entry = f.entry()
            assertEquals(32 * 1024, f.budget.snapshot().reservedBytes)
            assertEquals(0, f.budget.snapshot().allocatedBytes)
            val callbacks = f.server.stats().loops.sumOf { it.readinessCallbacks }
            assertNoData(client)
            assertEquals(callbacks, f.server.stats().loops.sumOf { it.readinessCallbacks })
            f.owner(entry) {
                assertEquals(0, entry.client.session.snapshot().bufferBytes)
                assertEquals(SelectionKey.OP_READ, entry.upstream.interestOps())
            }
        } } }
    }

    @Test fun exhaustedGlobalBudgetRejectsNewSessionAndReleaseAllowsRecovery() = target { target ->
        Fixture(budget = SocksTcpBufferBudget(capacityBytes = 32 * 1024)).use { f ->
            f.client(target.localPort).use { first ->
                target.accept().use { remote ->
                    reply(first); f.entry()
                    f.client(target.localPort).use { second ->
                        assertEquals(1, reply(second)[1].toInt()); assertEquals(-1, second.getInputStream().read())
                    }
                    assertEquals(1, f.channels.size)
                    assertEquals(1L, f.budget.snapshot().rejectedReservations)
                    remote.getOutputStream().write(byteArrayOf(9)); assertArrayEquals(byteArrayOf(9), read(first, 1))
                }
            }
            await { f.budget.snapshot().reservedBytes == 0 }
            assertEquals(0, f.budget.snapshot().allocatedBytes)
            f.client(target.localPort).use { third -> target.accept().use {
                assertEquals(0, reply(third)[1].toInt()); f.entry()
            } }
        }
    }

    @Test fun realSlowReceiverIsBoundedAndOtherConnectionsOnSameLoopStayResponsive() = target { target ->
        Fixture(prepare = { it.sendBufferSize = 4096 }).use { f ->
            f.client(target.localPort).use { slowClient -> target.accept().use { slowRemote ->
                slowRemote.receiveBufferSize = 4096
                reply(slowClient); val slowEntry = f.entry()
                val worker = Executors.newSingleThreadExecutor()
                val sent = worker.submit { runCatching { slowClient.getOutputStream().write(payload(4 * 1024 * 1024, 83)) } }
                try {
                    await { f.inspect(slowEntry).clientToUpstream.readPaused }
                    assertTrue(f.budget.snapshot().allocatedBytes <= 32 * 1024)
                    val clients = ArrayList<Socket>(); val remotes = ArrayList<Socket>()
                    try {
                        val fastEntries = (1..2).map {
                            val client = f.client(target.localPort).also(clients::add)
                            val remote = target.accept().also(remotes::add)
                            reply(client); val entry = f.entry()
                            val body = payload(4096, it)
                            client.getOutputStream().write(body)
                            assertArrayEquals(body, read(remote, body.size))
                            remote.getOutputStream().write(body)
                            assertArrayEquals(body, read(client, body.size))
                            entry
                        }
                        assertTrue(fastEntries.any { it.client.session.owner === slowEntry.client.session.owner })
                        assertTrue(f.budget.snapshot().peakAllocatedBytes <= 3 * 32 * 1024)
                    } finally { clients.forEach(Socket::close); remotes.forEach(Socket::close) }
                } finally {
                    slowClient.close(); slowRemote.close(); sent.get(3, TimeUnit.SECONDS)
                    worker.shutdownNow(); assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS))
                }
            } }
        }
    }

    @Test fun relayReadErrorReleasesBudgetChannelsAndTcpSlot() = target { target ->
        Fixture(io = object : TcpRelay.UpstreamIo {
            override fun read(channel: SocketChannel, target: ByteBuffer): Int = throw IOException("relay read")
        }).use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); remote.getOutputStream().write(byteArrayOf(1))
            assertEquals(-1, client.getInputStream().read()); f.released()
            f.owner(entry) { assertEquals("relay read", entry.client.session.snapshot().closeCause!!.message) }
        } } }
    }

    @Test fun relayWriteErrorReleasesBudgetAndWipesBuffers() = target { target ->
        Fixture(io = object : TcpRelay.UpstreamIo {
            override fun write(channel: SocketChannel, source: ByteBuffer): Int = throw IOException("relay write")
        }).use { f -> f.client(target.localPort).use { client -> target.accept().use {
            reply(client); val entry = f.entry(); client.getOutputStream().write(payload(1000, 97))
            assertEquals(-1, client.getInputStream().read()); f.released()
            f.owner(entry) { assertEquals(0, entry.client.session.snapshot().bufferBytes) }
        } } }
    }

    @Test fun timerRejectionWhileBackpressuredClosesInsteadOfSpinning() = target { target ->
        Fixture(config = SocksEventLoopConfig(timerCapacity = 1, timersPerTurn = 1),
            io = object : TcpRelay.UpstreamIo { override fun write(channel: SocketChannel, source: ByteBuffer) = 0 }
        ).use { f -> f.client(target.localPort).use { client -> target.accept().use {
            reply(client); val entry = f.entry()
            f.owner(entry) { assertEquals(SocksEventLoop.Submission.ACCEPTED,
                entry.client.session.owner.schedule(TimeUnit.SECONDS.toNanos(30), entry.client.session.resource) {}.result) }
            client.getOutputStream().write(byteArrayOf(1))
            assertEquals(-1, client.getInputStream().read()); f.released()
            f.owner(entry) { assertTrue(entry.client.session.snapshot().closeCause is SocksSession.SchedulingRejectedException) }
        } } }
    }

    @Test fun reservedBuffersReleaseWhenPreparationFailsBeforeRelayStarts() {
        Fixture(prepare = { throw IOException("prepare") }).use { f ->
            f.client(80).use { client -> assertEquals(1, reply(client)[1].toInt()); assertEquals(-1, client.getInputStream().read()) }
            f.released(); assertEquals(0, f.budget.snapshot().peakAllocatedBytes)
        }
    }

    @Test fun stopReleasesBothBufferedDirectionsAndTheirRetryTimers() = target { target ->
        val relayPhase = AtomicBoolean()
        Fixture(io = object : TcpRelay.UpstreamIo { override fun write(channel: SocketChannel, source: ByteBuffer) = 0 },
            clientIo = object : SocksNioHandshake.ClientIo {
                override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
                override fun write(channel: SocketChannel, source: ByteBuffer) = if (relayPhase.get()) 0 else channel.write(source)
            }).use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); relayPhase.set(true)
            client.getOutputStream().write(payload(32 * 1024, 101))
            remote.getOutputStream().write(payload(32 * 1024, 103))
            await { f.inspect(entry).let { it.clientToUpstream.readPaused && it.upstreamToClient.readPaused } }
            assertEquals(32 * 1024, f.budget.snapshot().allocatedBytes)
            assertTrue(f.server.stop()); f.released()
        } } }
    }

    @Test fun clientFinPreservesDelayedResponseWithoutDeadlineOrReadinessSpin() = target { target ->
        Fixture().use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); val body = payload(700, 107)
            client.getOutputStream().write(body); client.shutdownOutput()
            assertArrayEquals(body, read(remote, body.size)); assertEquals(-1, remote.getInputStream().read())
            f.owner(entry) {
                assertEquals(SocksSession.State.DRAINING, entry.client.session.snapshot().state)
                assertNull(entry.client.session.snapshot().deadlineNanos)
                assertTrue(entry.handle.snapshot().clientToUpstream.outputShutdown)
                assertEquals(SelectionKey.OP_READ, entry.upstream.interestOps())
            }
            assertEquals(1, f.server.stats().admission!!.tcp.current)
            assertEquals(0, f.server.stats().loops.sumOf { it.timers })
            val callbacks = f.server.stats().loops.sumOf { it.readinessCallbacks }
            assertNoData(client) // FIN has reached the peer; leave its output idle before replying.
            assertEquals(callbacks, f.server.stats().loops.sumOf { it.readinessCallbacks })
            val response = payload(48 * 1024, 109)
            remote.getOutputStream().write(response); remote.shutdownOutput()
            assertArrayEquals(response, read(client, response.size)); assertEquals(-1, client.getInputStream().read())
            f.normalClosed(entry, body.size, response.size)
        } } }
    }

    @Test fun upstreamFinStillAllowsDelayedClientUpload() = target { target ->
        Fixture().use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); val response = payload(1700, 113)
            remote.getOutputStream().write(response); remote.shutdownOutput()
            assertArrayEquals(response, read(client, response.size)); assertEquals(-1, client.getInputStream().read())
            f.owner(entry) {
                assertEquals(SocksSession.State.DRAINING, entry.client.session.snapshot().state)
                assertTrue(entry.handle.snapshot().upstreamToClient.outputShutdown)
                assertEquals(0, entry.upstream.interestOps())
            }
            assertNoData(remote)
            val body = payload(48 * 1024, 127)
            client.getOutputStream().write(body); client.shutdownOutput()
            assertArrayEquals(body, read(remote, body.size)); assertEquals(-1, remote.getInputStream().read())
            f.normalClosed(entry, body.size, response.size)
        } } }
    }

    @Test fun uploadFinWaitsForPendingPartialWritesWhileReverseDirectionFinishes() = target { target ->
        val allow = AtomicBoolean(); val shutdowns = AtomicInteger()
        Fixture(io = object : TcpRelay.UpstreamIo {
            override fun write(channel: SocketChannel, source: ByteBuffer) =
                if (allow.get()) limited(source, 7) { channel.write(it) } else 0
            override fun shutdownOutput(channel: SocketChannel) { shutdowns.incrementAndGet(); channel.shutdownOutput() }
        }).use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); val body = payload(1000, 131)
            client.getOutputStream().write(body); client.shutdownOutput()
            await { f.inspect(entry).clientToUpstream.sourceEof }
            assertEquals(body.size, f.inspect(entry).clientToUpstream.queuedBytes)
            assertEquals(0, shutdowns.get()); assertNoData(remote)
            remote.getOutputStream().write(byteArrayOf(21)); remote.shutdownOutput()
            assertArrayEquals(byteArrayOf(21), read(client, 1)); assertEquals(-1, client.getInputStream().read())
            assertEquals(1, f.server.stats().admission!!.tcp.current)
            allow.set(true)
            assertArrayEquals(body, read(remote, body.size)); assertEquals(-1, remote.getInputStream().read())
            f.normalClosed(entry, body.size, 1); assertEquals(1, shutdowns.get())
        } } }
    }

    @Test fun downloadFinWaitsForPendingPartialWritesWhileUploadFinishes() = target { target ->
        val relayPhase = AtomicBoolean(); val allow = AtomicBoolean(); val shutdowns = AtomicInteger()
        Fixture(clientIo = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
            override fun write(channel: SocketChannel, source: ByteBuffer) =
                if (relayPhase.get() && !allow.get()) 0 else limited(source, 3) { channel.write(it) }
            override fun shutdownOutput(channel: SocketChannel) { shutdowns.incrementAndGet(); channel.shutdownOutput() }
        }).use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); relayPhase.set(true); val response = payload(1000, 137)
            remote.getOutputStream().write(response); remote.shutdownOutput()
            await { f.inspect(entry).upstreamToClient.sourceEof }
            assertEquals(response.size, f.inspect(entry).upstreamToClient.queuedBytes)
            assertEquals(0, shutdowns.get()); assertNoData(client)
            client.getOutputStream().write(byteArrayOf(22)); client.shutdownOutput()
            assertArrayEquals(byteArrayOf(22), read(remote, 1)); assertEquals(-1, remote.getInputStream().read())
            assertEquals(1, f.server.stats().admission!!.tcp.current)
            allow.set(true)
            assertArrayEquals(response, read(client, response.size)); assertEquals(-1, client.getInputStream().read())
            f.normalClosed(entry, 1, response.size); assertEquals(1, shutdowns.get())
        } } }
    }

    @Test fun simultaneousFinDrainsLargeBidirectionalTraffic() = target { target ->
        Fixture().use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); val body = payload(512 * 1024, 139); val response = payload(512 * 1024, 149)
            val workers = Executors.newFixedThreadPool(4)
            try {
                val upload = workers.submit { client.getOutputStream().write(body); client.shutdownOutput() }
                val download = workers.submit { remote.getOutputStream().write(response); remote.shutdownOutput() }
                val received = workers.submit<ByteArray> { read(remote, body.size).also { assertEquals(-1, remote.getInputStream().read()) } }
                val returned = workers.submit<ByteArray> { read(client, response.size).also { assertEquals(-1, client.getInputStream().read()) } }
                assertArrayEquals(body, received.get(10, TimeUnit.SECONDS)); assertArrayEquals(response, returned.get(10, TimeUnit.SECONDS))
                upload.get(10, TimeUnit.SECONDS); download.get(10, TimeUnit.SECONDS)
                f.normalClosed(entry, body.size, response.size)
            } finally { workers.shutdownNow(); assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS)) }
        } } }
    }

    @Test fun bothEmptyFinsShutdownEachOutputOnceAndReleaseAdmissionForReuse() = target { target ->
        val upstreamShutdowns = AtomicInteger(); val clientShutdowns = AtomicInteger()
        Fixture(budget = SocksTcpBufferBudget(capacityBytes = 32 * 1024), io = object : TcpRelay.UpstreamIo {
            override fun shutdownOutput(channel: SocketChannel) { upstreamShutdowns.incrementAndGet(); channel.shutdownOutput() }
        }, clientIo = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
            override fun write(channel: SocketChannel, source: ByteBuffer) = channel.write(source)
            override fun shutdownOutput(channel: SocketChannel) { clientShutdowns.incrementAndGet(); channel.shutdownOutput() }
        }).use { f -> repeat(8) { iteration ->
            f.client(target.localPort).use { client -> target.accept().use { remote ->
                reply(client); val entry = f.entry(); client.shutdownOutput(); remote.shutdownOutput()
                assertEquals(-1, client.getInputStream().read()); assertEquals(-1, remote.getInputStream().read())
                f.normalClosed(entry, 0, 0)
                assertEquals(iteration + 1, upstreamShutdowns.get()); assertEquals(iteration + 1, clientShutdowns.get())
            } }
        } }
    }

    @Test fun realUpstreamResetClosesBothChannelsWithAnException() = target { target ->
        Fixture().use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); remote.setSoLinger(true, 0); remote.close()
            f.abnormalClosed(entry)
        } } }
    }

    @Test fun realClientResetClosesBothChannelsWithAnException() = target { target ->
        Fixture().use { f -> f.client(target.localPort).use { client -> target.accept().use {
            reply(client); val entry = f.entry(); client.setSoLinger(true, 0); client.close()
            f.abnormalClosed(entry)
        } } }
    }

    @Test fun resetAfterClientFinDoesNotMasqueradeAsNormalCompletion() = target { target ->
        Fixture().use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); client.shutdownOutput()
            assertEquals(-1, remote.getInputStream().read())
            remote.setSoLinger(true, 0); remote.close(); f.abnormalClosed(entry)
        } } }
    }

    @Test fun clientReadErrorAfterReverseFinUsesOneScopeCleanup() = target { target ->
        val fail = AtomicBoolean()
        Fixture(clientIo = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) =
                if (fail.get()) throw IOException("client read after FIN") else channel.read(target)
            override fun write(channel: SocketChannel, source: ByteBuffer) = channel.write(source)
        }).use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); remote.shutdownOutput(); assertEquals(-1, client.getInputStream().read())
            fail.set(true); client.getOutputStream().write(byteArrayOf(31))
            f.abnormalClosed(entry, "client read after FIN")
        } } }
    }

    @Test fun clientWriteErrorAfterClientFinUsesOneScopeCleanup() = target { target ->
        val fail = AtomicBoolean()
        Fixture(clientIo = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
            override fun write(channel: SocketChannel, source: ByteBuffer) =
                if (fail.get()) throw IOException("client write after FIN") else channel.write(source)
        }).use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); client.shutdownOutput(); assertEquals(-1, remote.getInputStream().read())
            fail.set(true); remote.getOutputStream().write(byteArrayOf(32))
            f.abnormalClosed(entry, "client write after FIN")
        } } }
    }

    @Test fun upstreamOutputShutdownFailureIsAnAbnormalCloseAndNeverRetried() = target { target ->
        val calls = AtomicInteger()
        Fixture(io = object : TcpRelay.UpstreamIo {
            override fun shutdownOutput(channel: SocketChannel) { calls.incrementAndGet(); throw IOException("upstream shutdown") }
        }).use { f -> f.client(target.localPort).use { client -> target.accept().use {
            reply(client); val entry = f.entry(); client.shutdownOutput()
            f.abnormalClosed(entry, "upstream shutdown"); assertEquals(1, calls.get())
        } } }
    }

    @Test fun clientOutputShutdownFailureAfterDrainIsAbnormalAndNeverRetried() = target { target ->
        val calls = AtomicInteger()
        Fixture(clientIo = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
            override fun write(channel: SocketChannel, source: ByteBuffer) = limited(source, 7) { channel.write(it) }
            override fun shutdownOutput(channel: SocketChannel) { calls.incrementAndGet(); throw IOException("client shutdown") }
        }).use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); val body = payload(1000, 151)
            remote.getOutputStream().write(body); remote.shutdownOutput()
            assertArrayEquals(body, read(client, body.size))
            f.abnormalClosed(entry, "client shutdown"); assertEquals(1, calls.get())
        } } }
    }

    @Test fun clientShutdownHandleRejectsOtherThreadsAndClosedSessions() = target { target ->
        Fixture().use { f -> f.client(target.localPort).use { client -> target.accept().use {
            reply(client); val entry = f.entry()
            assertThrows(IllegalStateException::class.java) { entry.client.shutdownOutput() }
            f.owner(entry) {
                entry.client.session.close()
                assertThrows(IllegalStateException::class.java) { entry.client.shutdownOutput() }
            }
            f.released()
        } } }
    }

    @Test fun stopWhileBothFinsWaitForDrainCancelsRetriesAndReleasesEverything() = target { target ->
        val relayPhase = AtomicBoolean(); val shutdowns = AtomicInteger()
        Fixture(io = object : TcpRelay.UpstreamIo {
            override fun write(channel: SocketChannel, source: ByteBuffer) = 0
            override fun shutdownOutput(channel: SocketChannel) { shutdowns.incrementAndGet(); channel.shutdownOutput() }
        }, clientIo = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
            override fun write(channel: SocketChannel, source: ByteBuffer) = if (relayPhase.get()) 0 else channel.write(source)
            override fun shutdownOutput(channel: SocketChannel) { shutdowns.incrementAndGet(); channel.shutdownOutput() }
        }).use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
            reply(client); val entry = f.entry(); relayPhase.set(true)
            client.getOutputStream().write(payload(1000, 157)); client.shutdownOutput()
            remote.getOutputStream().write(payload(1000, 163)); remote.shutdownOutput()
            await { f.inspect(entry).let { it.clientToUpstream.sourceEof && it.upstreamToClient.sourceEof } }
            assertEquals(0, shutdowns.get()); assertEquals(1, f.server.stats().admission!!.tcp.current)
            assertTrue(f.server.stop()); f.released(); assertEquals(0, shutdowns.get())
        } } }
    }

    @Test fun stopAtOutputShutdownNeverWaitsOnOwnerAndCleanupStaysIdempotent() = target { target ->
        repeat(8) {
            val fixture = AtomicReference<Fixture>(); val shutdowns = AtomicInteger(); val called = CountDownLatch(1)
            Fixture(io = object : TcpRelay.UpstreamIo {
                override fun shutdownOutput(channel: SocketChannel) {
                    shutdowns.incrementAndGet(); channel.shutdownOutput()
                    assertFalse(fixture.get().server.stop()) // owner-only stop request, no joins
                    called.countDown()
                }
            }).use { f -> fixture.set(f); f.client(target.localPort).use { client -> target.accept().use {
                reply(client); f.entry(); client.shutdownOutput()
                assertTrue(called.await(3, TimeUnit.SECONDS)); assertTrue(f.server.stop())
                f.released(); assertEquals(1, shutdowns.get())
                assertEquals(0L, f.server.stats().loops.sumOf { it.callbackFailures })
            } } }
        }
    }

    @Test fun concurrentStopAndFinalFinReleaseExactlyOnceAcrossRestarts() = target { target ->
        repeat(8) {
            Fixture().use { f -> f.client(target.localPort).use { client -> target.accept().use { remote ->
                reply(client); f.entry(); client.shutdownOutput(); assertEquals(-1, remote.getInputStream().read())
                val worker = Executors.newSingleThreadExecutor()
                try {
                    val stopped = worker.submit<Boolean> { f.server.stop() }
                    remote.shutdownOutput(); assertTrue(stopped.get(3, TimeUnit.SECONDS)); f.released()
                    assertEquals(0L, f.server.stats().loops.sumOf { it.callbackFailures })
                } finally { worker.shutdownNow(); assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS)) }
            } } }
        }
    }

    private data class Entry(val client: SocksNioHandshake.AdmittedRequest,
        val upstream: SocksEventLoop.Registration, val handle: TcpRelay.Handle)

    private inner class Fixture(
        val budget: SocksTcpBufferBudget = SocksTcpBufferBudget(),
        io: TcpRelay.UpstreamIo = TcpRelay.UpstreamIo.CHANNEL,
        clientIo: SocksNioHandshake.ClientIo = SocksNioHandshake.ClientIo.CHANNEL,
        prepare: (Socket) -> Unit = {}, config: SocksEventLoopConfig = SocksEventLoopConfig()
    ) : AutoCloseable {
        val channels = ConcurrentLinkedQueue<SocketChannel>()
        private val entries = ConcurrentLinkedQueue<Entry>()
        val relay = TcpRelay(budget, io)
        val connector = SocksNioTcpConnect(prepare, { connection ->
            val handle = checkNotNull(relay.start(connection))
            entries.add(Entry(connection.client, connection.upstream, handle))
        }, io = object : SocksNioTcpConnect.ConnectIo { override fun open() = SocketChannel.open().also(channels::add) })
        val server = SocksNioServer(SocksNioHandshake({ credentials }, { entry ->
            if (relay.reserve(entry.session)) connector.connect(entry)
            else connector.connectResolved(entry, emptyList(), entry.session.ownerNowNanos() + TimeUnit.SECONDS.toNanos(15))
        }, clientIo), config = config).also { it.start() }

        fun client(port: Int, body: ByteArray = byteArrayOf()) = Socket().also {
            it.soTimeout = 5000; it.connect(InetSocketAddress(loopback, server.stats().port!!))
            it.getOutputStream().write(handshake + SocksProtocol.encodeRequest(SocksRequest(1, SocksDestination.Ip(loopback), port)) + body)
            assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(it, 4))
        }

        fun entry(): Entry { await { entries.isNotEmpty() }; return checkNotNull(entries.poll()) }
        fun inspect(entry: Entry): TcpRelay.Snapshot {
            val result = AtomicReference<TcpRelay.Snapshot>(); owner(entry) { result.set(entry.handle.snapshot()) }
            return result.get()
        }
        fun owner(entry: Entry, action: () -> Unit) {
            val done = CountDownLatch(1); val error = AtomicReference<Throwable>()
            assertEquals(SocksEventLoop.Submission.ACCEPTED, entry.client.session.owner.submit {
                try { action() } catch (caught: Throwable) { error.set(caught) } finally { done.countDown() }
            })
            assertTrue(done.await(5, TimeUnit.SECONDS)); error.get()?.let { throw it }
        }
        fun released() {
            await { server.stats().admission!!.tcp.current == 0 && budget.snapshot().reservedBytes == 0 }
            assertEquals(0, budget.snapshot().allocatedBytes)
            assertTrue(channels.none { it.isOpen })
        }
        fun normalClosed(entry: Entry, uploadBytes: Int, downloadBytes: Int) {
            released()
            owner(entry) {
                val snapshot = entry.client.session.snapshot()
                assertEquals(SocksSession.State.CLOSED, snapshot.state); assertNull(snapshot.closeCause)
                assertEquals(0, snapshot.bufferBytes); assertFalse(snapshot.hasProtocolLease)
                val relay = entry.handle.snapshot()
                listOf(relay.clientToUpstream, relay.upstreamToClient).forEach {
                    assertTrue(it.sourceEof); assertTrue(it.outputShutdown); assertEquals(0, it.queuedBytes)
                }
                assertEquals(uploadBytes.toLong(), relay.clientToUpstream.writtenBytes)
                assertEquals(downloadBytes.toLong(), relay.upstreamToClient.writtenBytes)
                entry.client.session.close(IOException("late duplicate"))
                assertNull(entry.client.session.snapshot().closeCause)
            }
            assertEquals(0L, server.stats().loops.sumOf { it.callbackFailures })
        }
        fun abnormalClosed(entry: Entry, message: String? = null) {
            released()
            owner(entry) {
                val snapshot = entry.client.session.snapshot()
                assertEquals(SocksSession.State.CLOSED, snapshot.state); assertTrue(snapshot.closeCause is IOException)
                if (message != null) assertEquals(message, snapshot.closeCause!!.message)
                assertEquals(0, snapshot.bufferBytes); assertFalse(snapshot.hasProtocolLease)
                entry.client.session.close()
                assertSame(snapshot.closeCause, entry.client.session.snapshot().closeCause)
            }
            assertEquals(1L, server.stats().loops.sumOf { it.callbackFailures })
        }
        override fun close() {
            assertTrue(server.stop()); released()
            val stats = server.stats(); assertEquals(SocksNioServer.State.STOPPED, stats.state)
            assertEquals(0, stats.admission!!.handshakes.current); assertEquals(0, stats.admission.udp.current)
            assertEquals(listOf(0, 0), stats.admission.ownerLoads)
            stats.loops.forEach {
                assertEquals(0, it.channels); assertEquals(0, it.keys); assertEquals(0, it.resources)
                assertEquals(0, it.timers); assertEquals(0L, it.cleanupFailures)
            }
        }
    }

    private fun target(action: (ServerSocket) -> Unit) = ServerSocket(0, 32, loopback).use {
        it.soTimeout = 5000; action(it)
    }
    private fun payload(size: Int, seed: Int) = ByteArray(size) { ((it * seed + it / 251) and 255).toByte() }
    private fun read(socket: Socket, size: Int): ByteArray {
        socket.soTimeout = 5000
        val bytes = ByteArray(size); var offset = 0
        while (offset < size) {
            val count = socket.getInputStream().read(bytes, offset, size - offset)
            assertTrue("early EOF at $offset/$size", count > 0); offset += count
        }
        return bytes
    }
    private fun reply(socket: Socket): ByteArray {
        val header = read(socket, 4); assertEquals(5, header[0].toInt()); assertEquals(0, header[2].toInt())
        return header + read(socket, if (header[3].toInt() == 1) 6 else 18)
    }
    private fun assertNoData(socket: Socket) {
        val old = socket.soTimeout; socket.soTimeout = 120
        try { assertThrows(SocketTimeoutException::class.java) { socket.getInputStream().read() } }
        finally { socket.soTimeout = old }
    }
    private fun limited(buffer: ByteBuffer, maxBytes: Int, action: (ByteBuffer) -> Int): Int {
        val old = buffer.limit(); buffer.limit(buffer.position() + minOf(buffer.remaining(), maxBytes))
        return try { action(buffer) } finally { buffer.limit(old) }
    }
    private fun await(condition: () -> Boolean) {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(8)
        while (!condition()) { assertTrue("condition deadline", System.nanoTime() < until); Thread.sleep(2) }
    }
}
