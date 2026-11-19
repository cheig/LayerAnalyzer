package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.tls.SocksNioTlsGateway
import com.example.layanalyzer.capture.tls.TlsGatewayChannel
import com.example.layanalyzer.capture.tls.TlsGatewayConnection
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
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class SocksNioGatewayConnectTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val credentials = SocksCredentials.of("User", "Password")
    private val handshake = byteArrayOf(5, 1, 2, 1, 4) + "User".toByteArray() +
        byteArrayOf(8) + "Password".toByteArray()
    private val requestFrame = frame("secret metadata".toByteArray())
    private val readyFrame = replyFrame("{\"version\":1,\"success\":true,\"errorCode\":null}")

    @Test fun realSelectorPartialAndZeroFrameWritesAndOneByteReadyReads() = gateway { remote ->
        val writes = AtomicInteger()
        val reads = AtomicInteger()
        val io = object : SocksNioGatewayConnect.GatewayIo {
            override fun write(channel: SocketChannel, source: ByteBuffer): Int =
                if (writes.incrementAndGet() % 2 == 1) 0 else limited(source, 1) { channel.write(it) }
            override fun read(channel: SocketChannel, target: ByteBuffer): Int =
                if (reads.incrementAndGet() % 2 == 1) 0 else limited(target, 1) { channel.read(it) }
        }
        Fixture(remote.localPort, io = io).use { f -> f.client().use { client ->
            remote.accept().use { hop ->
                assertArrayEquals(requestFrame, read(hop, requestFrame.size))
                val entry = f.entry()
                f.owner(entry) {
                    assertEquals(SocksSession.State.GATEWAY_READY, it.session.snapshot().state)
                    assertTrue(f.frames.all(::wiped))
                }
                assertNoData(client)
                hop.getOutputStream().write(readyFrame)
                val ready = f.ready()
                f.owner(entry) {
                    assertEquals(SocksSession.State.GATEWAY_READY, it.session.snapshot().state)
                    assertEquals(0, ready.upstream.interestOps())
                    assertEquals(0, it.session.snapshot().bufferBytes)
                }
                assertTrue(writes.get() >= requestFrame.size * 2)
                assertTrue(reads.get() >= readyFrame.size * 2)
                assertEquals(1L, f.connector.stats().ready)
                assertNoData(client)
            }
        } }
    }

    @Test fun readyCoalescedWithDownstreamLeavesAllApplicationBytesOnChannel() = gateway { remote ->
        Fixture(remote.localPort).use { f -> f.client(payload = byteArrayOf(22, 23, 24)).use { client ->
            remote.accept().use { hop ->
                read(hop, requestFrame.size)
                val bytes = ByteArray(8192) { (it * 17).toByte() }
                hop.getOutputStream().write(readyFrame + bytes)
                val ready = f.ready()
                val received = ByteBuffer.allocate(bytes.size)
                f.owner(ready.client) {
                    assertEquals(3, it.bufferedClientBytes)
                    assertEquals(0, ready.upstream.interestOps())
                    while (received.hasRemaining()) assertTrue((ready.upstream.channel as SocketChannel).read(received) > 0)
                }
                assertArrayEquals(bytes, received.array())
                assertNoData(client)
                assertNoData(hop)
            }
        } }
    }

    @Test fun maximumLat1FrameHasOneOwnedAllocationAndIsWipedAfterDrain() = gateway { remote ->
        val full = frame(ByteArray(TlsGatewayChannel.MAX_HEADER_BYTES) { 65 })
        val allow = AtomicBoolean()
        Fixture(remote.localPort, bytes = full, io = object : SocksNioGatewayConnect.GatewayIo {
            override fun write(channel: SocketChannel, source: ByteBuffer) = if (allow.get()) channel.write(source) else 0
        }).use { f -> f.client().use {
            remote.accept().use { hop ->
                val entry = f.entry()
                await {
                    var writing = false
                    f.owner(entry) { writing = it.session.snapshot().state == SocksSession.State.GATEWAY_WRITE }
                    writing
                }
                f.owner(entry) {
                    assertEquals(SocksSession.State.GATEWAY_WRITE, it.session.snapshot().state)
                    assertEquals(4104, it.session.snapshot().bufferBytes)
                    assertEquals(1, it.session.snapshot().buffers)
                }
                allow.set(true)
                assertArrayEquals(full, read(hop, full.size))
                await { f.frames.all(::wiped) }
                hop.getOutputStream().write(readyFrame)
                f.ready()
            }
        } }
    }

    @Test fun fixedGatewayRefusalsUseLegacySocksMapping() = gateway { remote ->
        Fixture(remote.localPort).use { f ->
            val codes = listOf("INVALID_ARGUMENT", "NOT_READY", "UNSUPPORTED", "STALE_GENERATION", "CANCELLED",
                "IO_ERROR", "CAPACITY_EXCEEDED", "PROTECT_FAILED", "NETWORK_CHANGED", "UPSTREAM_CERT_INVALID",
                "DOWNSTREAM_TLS_REJECTED", "SECRETS_INCOMPLETE", "CAPTURE_CONTEXT_MISSING", "FUTURE_CODE")
            codes.forEach { code -> f.client().use { client -> remote.accept().use { hop ->
                read(hop, requestFrame.size)
                hop.getOutputStream().write(replyFrame("{\"version\":1,\"success\":false,\"errorCode\":\"$code\"}"))
                assertFailure(client, SocksProtocol.replyForGatewayRefusal(code))
            } } }
            f.assertReleased()
            assertEquals(codes.size.toLong(), f.connector.stats().refusals)
            assertEquals(codes.size.toLong(), f.connector.stats().failures[SocksNioGatewayConnect.Stage.READY_READ])
            assertEquals(0L, f.connector.stats().ready)
        }
    }

    @Test fun malformedReadyFramingAndVerdictsCannotHandoff() = gateway { remote ->
        val bad = listOf(
            byteArrayOf(0, 0, 0, 0, 0, 0, 0, 1),
            ByteBuffer.allocate(8).putInt(TlsGatewayChannel.FRAME_MAGIC_INT).putInt(0).array(),
            ByteBuffer.allocate(8).putInt(TlsGatewayChannel.FRAME_MAGIC_INT).putInt(1025).array(),
            ByteBuffer.allocate(8).putInt(TlsGatewayChannel.FRAME_MAGIC_INT).putInt(-1).array(),
            replyFrame("not-json"), replyFrame("[]"), replyFrame("{}"),
            replyFrame("{\"version\":2,\"success\":true}"),
            replyFrame("{\"version\":1,\"success\":\"true\"}"),
            replyFrame("{\"version\":1,\"success\":true,\"errorCode\":\"IO_ERROR\"}"),
            replyFrame("{\"version\":1,\"success\":false}"),
            replyFrame("{\"version\":1,\"success\":false,\"errorCode\":0}"),
            replyFrame("{\"version\":1,\"success\":false,\"errorCode\":\"\"}"),
            replyFrame("{\"version\":1,\"success\":true}{}"),
            frame(byteArrayOf(0xc3.toByte(), 0x28))
        )
        Fixture(remote.localPort).use { f ->
            bad.forEach { bytes -> f.client().use { client -> remote.accept().use { hop ->
                read(hop, requestFrame.size)
                hop.getOutputStream().write(bytes)
                assertFailure(client)
            } } }
            assertEquals(bad.size, f.errors.count { it.reason == SocksNioGatewayConnect.Reason.MALFORMED })
            assertEquals(0L, f.connector.stats().ready)
            f.assertReleased()
        }
    }

    @Test fun eofAtEveryReadyBoundaryFailsAndReleasesBuffers() = gateway { remote ->
        Fixture(remote.localPort).use { f ->
            listOf(0, 1, 7, 8, 9, readyFrame.size - 1).forEach { length -> f.client().use { client ->
                remote.accept().use { hop ->
                    read(hop, requestFrame.size)
                    hop.getOutputStream().write(readyFrame.copyOf(length))
                    hop.shutdownOutput()
                    assertFailure(client)
                }
            } }
            assertEquals(6, f.errors.count { it.reason == SocksNioGatewayConnect.Reason.IO })
            f.assertReleased()
        }
    }

    @Test fun metadataFailureNeverCreatesChannel() {
        Fixture(9, describe = { throw IOException("metadata unavailable") }).use { f ->
            f.client().use(::assertFailure)
            assertTrue(f.channels.isEmpty())
            assertEquals(SocksNioGatewayConnect.Stage.DESCRIPTION, f.errors.single().stage)
            f.assertReleased()
        }
    }

    @Test fun protectionFailureNeverConnectsAndWipesFrame() {
        val dials = AtomicInteger()
        Fixture(9, prepare = { throw IOException("protect") }, io = object : SocksNioGatewayConnect.GatewayIo {
            override fun connect(channel: SocketChannel, endpoint: InetSocketAddress): Boolean {
                dials.incrementAndGet(); return false
            }
        }).use { f ->
            f.client().use(::assertFailure)
            assertEquals(0, dials.get())
            assertEquals(SocksNioGatewayConnect.Stage.HOP_CONNECT, f.errors.single().stage)
            f.assertReleased()
        }
    }

    @Test fun openFactoryFailureWipesFrameAndReplies() {
        Fixture(9, factory = { throw IOException("open") }).use { f ->
            f.client().use(::assertFailure)
            f.assertReleased()
        }
    }

    @Test fun registrationCapacityFailureClosesUnregisteredChannelAndDescription() {
        Fixture(9, config = SocksEventLoopConfig(channelCapacity = 2, readinessPerTurn = 2)).use { f ->
            f.client().use { assertEquals(-1, it.getInputStream().read()) }
            f.assertReleased()
        }
    }

    @Test fun realRefusedHopUsesGeneralFailure() {
        val port = ServerSocket(0, 1, loopback).use { it.localPort }
        Fixture(port).use { f -> f.client().use(::assertFailure); f.assertReleased() }
    }

    @Test fun hopConnectDeadlineDoesNotWaitForReadyBudget() = gateway { remote ->
        val calls = AtomicInteger()
        Fixture(remote.localPort, connectBudget = TimeUnit.MILLISECONDS.toNanos(80),
            io = pendingConnect(calls)).use { f ->
            f.client().use(::assertFailure)
            assertTrue(calls.get() > 0)
            assertEquals(SocksNioGatewayConnect.Stage.HOP_CONNECT, f.errors.single().stage)
            assertEquals(1L, f.connector.stats().timeouts)
            f.assertReleased()
        }
    }

    @Test fun finishConnectExceptionIsObservableAtHopStage() = gateway { remote ->
        Fixture(remote.localPort, io = object : SocksNioGatewayConnect.GatewayIo {
            override fun finishConnect(channel: SocketChannel): Boolean = throw IOException("finish")
        }).use { f ->
            f.client().use(::assertFailure)
            assertEquals(SocksNioGatewayConnect.Stage.HOP_CONNECT, f.errors.single().stage)
            f.assertReleased()
        }
    }

    @Test fun frameWriteExceptionIsObservableAndWipesPendingSecret() = gateway { remote ->
        Fixture(remote.localPort, io = object : SocksNioGatewayConnect.GatewayIo {
            override fun write(channel: SocketChannel, source: ByteBuffer): Int = throw IOException("write")
        }).use { f ->
            f.client().use(::assertFailure)
            assertEquals(SocksNioGatewayConnect.Stage.LAT1_WRITE, f.errors.single().stage)
            f.assertReleased()
        }
    }

    @Test fun readyReadExceptionIsObservableAndReleasesInputBuffer() = gateway { remote ->
        Fixture(remote.localPort, io = object : SocksNioGatewayConnect.GatewayIo {
            override fun read(channel: SocketChannel, target: ByteBuffer): Int = throw IOException("read")
        }).use { f -> f.client().use { client -> remote.accept().use { hop ->
            read(hop, requestFrame.size)
            hop.getOutputStream().write(readyFrame)
            assertFailure(client)
            assertEquals(SocksNioGatewayConnect.Stage.READY_READ, f.errors.single().stage)
            f.assertReleased()
        } } }
    }

    @Test fun repeatedPartialFrameProgressCannotRenewWriteDeadline() = gateway { remote ->
        val now = AtomicLong(System.nanoTime())
        val calls = AtomicInteger()
        Fixture(remote.localPort, clock = now::get, readyBudget = TimeUnit.SECONDS.toNanos(1),
            io = object : SocksNioGatewayConnect.GatewayIo {
                override fun write(channel: SocketChannel, source: ByteBuffer): Int {
                    calls.incrementAndGet()
                    val count = limited(source, 1) { channel.write(it) }
                    now.addAndGet(TimeUnit.MILLISECONDS.toNanos(400))
                    return count
                }
            }).use { f ->
            f.client().use(::assertFailure)
            assertEquals(3, calls.get())
            assertEquals(SocksNioGatewayConnect.Stage.LAT1_WRITE, f.errors.single().stage)
            assertEquals(1L, f.connector.stats().timeouts)
            f.assertReleased()
        }
    }

    @Test fun readyHandoffCanEnterExistingSocksReplyAndCancelsSetupDeadline() = gateway { remote ->
        Fixture(remote.localPort, readyBudget = TimeUnit.MILLISECONDS.toNanos(100), readyAction = { ready ->
            assertTrue(ready.client.session.enterSocksReply(TimeUnit.SECONDS.toNanos(1)))
            assertTrue(ready.client.session.enterTcpConnected())
        }).use { f -> f.client().use { client -> remote.accept().use { hop ->
            read(hop, requestFrame.size)
            hop.getOutputStream().write(readyFrame)
            val ready = f.ready()
            client.soTimeout = 180
            assertThrows(SocketTimeoutException::class.java) { client.getInputStream().read() }
            f.owner(ready.client) {
                assertEquals(SocksSession.State.TCP_CONNECTED, it.session.snapshot().state)
                assertNull(it.session.snapshot().deadlineNanos)
            }
            assertTrue(f.errors.isEmpty())
        } } }
    }

    @Test fun zeroFrameWriteTimeoutIsBoundedAndLoopDoesNotSpin() = gateway { remote ->
        val calls = AtomicInteger()
        Fixture(remote.localPort, readyBudget = TimeUnit.MILLISECONDS.toNanos(100),
            io = object : SocksNioGatewayConnect.GatewayIo {
                override fun write(channel: SocketChannel, source: ByteBuffer): Int { calls.incrementAndGet(); return 0 }
            }).use { f ->
            f.client().use(::assertFailure)
            assertTrue("zero write busy loop: ${calls.get()}", calls.get() in 1..150)
            assertEquals(SocksNioGatewayConnect.Stage.LAT1_WRITE, f.errors.single().stage)
            assertEquals(1L, f.connector.stats().timeouts)
            f.assertReleased()
        }
    }

    @Test fun zeroReadyReadTimeoutDisarmsReadinessWithoutSpin() = gateway { remote ->
        val calls = AtomicInteger()
        Fixture(remote.localPort, readyBudget = TimeUnit.MILLISECONDS.toNanos(120),
            io = object : SocksNioGatewayConnect.GatewayIo {
                override fun read(channel: SocketChannel, target: ByteBuffer): Int { calls.incrementAndGet(); return 0 }
            }).use { f -> f.client().use { client -> remote.accept().use { hop ->
                read(hop, requestFrame.size)
                hop.getOutputStream().write(readyFrame)
                assertFailure(client)
                assertTrue("zero read busy loop: ${calls.get()}", calls.get() in 1..150)
                assertEquals(SocksNioGatewayConnect.Stage.READY_READ, f.errors.single().stage)
                f.assertReleased()
            } } }
    }

    @Test fun writeAndReadyShareDeadlineDespitePartialProgress() = gateway { remote ->
        val now = AtomicLong(System.nanoTime())
        val writes = AtomicInteger()
        Fixture(remote.localPort, clock = now::get, readyBudget = TimeUnit.SECONDS.toNanos(1),
            io = object : SocksNioGatewayConnect.GatewayIo {
                override fun write(channel: SocketChannel, source: ByteBuffer): Int {
                    val count = channel.write(source)
                    if (writes.incrementAndGet() == 1) now.addAndGet(TimeUnit.MILLISECONDS.toNanos(700))
                    return count
                }
                override fun read(channel: SocketChannel, target: ByteBuffer): Int {
                    val count = limited(target, 1) { channel.read(it) }
                    if (count > 0) now.addAndGet(TimeUnit.MILLISECONDS.toNanos(100))
                    return count
                }
            }).use { f -> f.client().use { client -> remote.accept().use { hop ->
                read(hop, requestFrame.size)
                hop.getOutputStream().write(readyFrame)
                assertFailure(client)
                assertEquals(SocksNioGatewayConnect.Stage.READY_READ, f.errors.single().stage)
                assertEquals(1L, f.connector.stats().timeouts)
                f.assertReleased()
            } } }
    }

    @Test fun expiredPreDnsDeadlineRejectsWithoutMetadataOrChannel() {
        val descriptions = AtomicInteger()
        Fixture(9, describe = { descriptions.incrementAndGet() }, admitted = { entry, connector ->
            connector.connectResolved(entry, loopback, entry.session.ownerNowNanos() - 1)
        }).use { f ->
            f.client().use(::assertFailure)
            assertEquals(0, descriptions.get())
            assertTrue(f.channels.isEmpty())
            assertEquals(1L, f.connector.stats().timeouts)
            f.assertReleased()
        }
    }

    @Test fun queuedDnsTimeIsSubtractedFromHopAndReadyTotal() = gateway { remote ->
        val now = AtomicLong(System.nanoTime())
        Fixture(remote.localPort, clock = now::get, admitted = { entry, connector ->
            val total = entry.session.ownerNowNanos() + SocksNioGatewayConnect.ESTABLISHMENT_TIMEOUT_NANOS
            assertTrue(entry.session.enterResolving(total) { error("should enter hop") })
            now.addAndGet(TimeUnit.SECONDS.toNanos(21))
            connector.connectResolved(entry, loopback, total)
        }, io = object : SocksNioGatewayConnect.GatewayIo {
            override fun read(channel: SocketChannel, target: ByteBuffer): Int {
                val count = channel.read(target)
                now.addAndGet(TimeUnit.MILLISECONDS.toNanos(1100))
                return count
            }
        }).use { f -> f.client().use { client -> remote.accept().use { hop ->
            read(hop, requestFrame.size)
            hop.getOutputStream().write(readyFrame)
            assertFailure(client)
            assertEquals(1L, f.connector.stats().timeouts)
            f.assertReleased()
        } } }
    }

    @Test fun customThirtySecondReadyCannotExtendExplicitTotalDeadline() = gateway { remote ->
        Fixture(remote.localPort, readyBudget = TimeUnit.SECONDS.toNanos(30), admitted = { entry, connector ->
            connector.connectResolved(entry, loopback, entry.session.ownerNowNanos() + TimeUnit.MILLISECONDS.toNanos(100))
        }).use { f -> f.client().use { client -> remote.accept().use { hop ->
            read(hop, requestFrame.size)
            assertFailure(client)
            assertEquals(SocksNioGatewayConnect.Stage.READY_READ, f.errors.single().stage)
            f.assertReleased()
        } } }
    }

    @Test fun dnsFailureHasFiniteGeneralFailureReplyAndStage() {
        Fixture(9, admitted = { entry, connector -> connector.fail(entry, IOException("DNS rejected")) }).use { f ->
            f.client().use(::assertFailure)
            assertEquals(SocksNioGatewayConnect.Stage.RESOLVING, f.errors.single().stage)
            assertTrue(f.channels.isEmpty())
            f.assertReleased()
        }
    }

    @Test fun failureReplySupportsPartialAndZeroWrites() {
        val calls = AtomicInteger()
        Fixture(9, describe = { throw IOException("unavailable") }, clientIo = object : SocksNioHandshake.ClientIo {
            override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
            override fun write(channel: SocketChannel, source: ByteBuffer): Int =
                if (calls.incrementAndGet() % 2 == 1) 0 else limited(source, 1) { channel.write(it) }
        }).use { f -> f.client().use(::assertFailure); f.assertReleased() }
    }

    @Test fun permanentlyUnwritableFailureReplyExpiresAndReleasesAllResources() {
        val calls = AtomicInteger()
        Fixture(9, describe = { throw IOException("unavailable") }, replyBudget = TimeUnit.MILLISECONDS.toNanos(100),
            clientIo = object : SocksNioHandshake.ClientIo {
                override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
                override fun write(channel: SocketChannel, source: ByteBuffer): Int =
                    if (source.remaining() > 2) { calls.incrementAndGet(); 0 } else channel.write(source)
            }).use { f ->
            f.client().use { assertEquals(-1, it.getInputStream().read()) }
            assertTrue(calls.get() in 1..150)
            f.assertReleased()
        }
    }

    @Test fun stopDuringConnectWipesFrameAndReturnsLease() = gateway { remote ->
        val calls = AtomicInteger()
        Fixture(remote.localPort, io = pendingConnect(calls)).use { f -> f.client().use { client ->
            await { calls.get() > 0 }
            f.stopAndAssert()
            assertEquals(-1, client.getInputStream().read())
        } }
    }

    @Test fun stopDuringPartialFrameWriteWipesFrameAndReturnsLease() = gateway { remote ->
        val calls = AtomicInteger()
        Fixture(remote.localPort, io = object : SocksNioGatewayConnect.GatewayIo {
            override fun write(channel: SocketChannel, source: ByteBuffer): Int =
                if (calls.incrementAndGet() == 1) limited(source, 1) { channel.write(it) } else 0
        }).use { f -> f.client().use { client ->
            await { calls.get() >= 2 }
            f.stopAndAssert()
            assertEquals(-1, client.getInputStream().read())
        } }
    }

    @Test fun stopDuringPartialReadyWipesBufferAndReturnsLease() = gateway { remote ->
        Fixture(remote.localPort).use { f -> f.client().use { client -> remote.accept().use { hop ->
            read(hop, requestFrame.size)
            hop.getOutputStream().write(readyFrame.copyOf(9))
            val entry = f.entry()
            await {
                var bodyAllocated = false
                f.owner(entry) { bodyAllocated = it.session.snapshot().bufferBytes == readyFrame.size - 8 }
                bodyAllocated
            }
            f.stopAndAssert()
            assertEquals(-1, client.getInputStream().read())
        } } }
    }

    @Test fun stopDuringProtectionClosesBeforeAnySynAndWipesDescription() {
        lateinit var f: Fixture
        val dials = AtomicInteger()
        f = Fixture(9, prepare = { f.server.stop() }, io = object : SocksNioGatewayConnect.GatewayIo {
            override fun connect(channel: SocketChannel, endpoint: InetSocketAddress): Boolean { dials.incrementAndGet(); return false }
        })
        f.use {
            f.client().use { assertEquals(-1, it.getInputStream().read()) }
            f.stopAndAssert()
            assertEquals(0, dials.get())
        }
    }

    @Test fun successorCallbackFailureClosesWithoutDuplicateGatewayFailure() = gateway { remote ->
        Fixture(remote.localPort, readyAction = { throw IOException("successor") }).use { f ->
            f.client().use { client -> remote.accept().use { hop ->
                read(hop, requestFrame.size)
                hop.getOutputStream().write(readyFrame)
                assertEquals(-1, client.getInputStream().read())
                f.assertReleased()
                assertEquals(1L, f.connector.stats().ready)
                assertEquals(0, f.errors.size)
            } }
        }
    }

    private inner class Fixture(
        port: Int,
        bytes: ByteArray = requestFrame,
        io: SocksNioGatewayConnect.GatewayIo = SocksNioGatewayConnect.GatewayIo.CHANNEL,
        prepare: (Socket) -> Unit = {},
        factory: () -> SocketChannel = { SocketChannel.open() },
        describe: () -> Unit = {},
        clientIo: SocksNioHandshake.ClientIo = SocksNioHandshake.ClientIo.CHANNEL,
        clock: () -> Long = System::nanoTime,
        connectBudget: Long = TimeUnit.SECONDS.toNanos(1),
        readyBudget: Long = TimeUnit.SECONDS.toNanos(11),
        replyBudget: Long = TimeUnit.SECONDS.toNanos(1),
        admitted: (SocksNioHandshake.AdmittedRequest, SocksNioGatewayConnect) -> Unit = { entry, connector ->
            connector.connectResolved(entry, loopback, entry.session.ownerNowNanos() + SocksNioGatewayConnect.ESTABLISHMENT_TIMEOUT_NANOS)
        },
        readyAction: (SocksNioGatewayConnect.Ready) -> Unit = {},
        config: SocksEventLoopConfig = SocksEventLoopConfig()
    ) : AutoCloseable {
        val channels = ConcurrentLinkedQueue<SocketChannel>()
        val frames = ConcurrentLinkedQueue<ByteBuffer>()
        val entries = ConcurrentLinkedQueue<SocksNioHandshake.AdmittedRequest>()
        val results = ConcurrentLinkedQueue<SocksNioGatewayConnect.Ready>()
        val errors = ConcurrentLinkedQueue<SocksNioGatewayConnect.Failure>()
        val gateway = object : SocksNioTlsGateway {
            override fun route(destinationPort: Int) = SocksNioTlsGateway.Route.GATEWAY
            override fun describe(destinationAddress: InetAddress, destinationPort: Int): TlsGatewayConnection {
                describe()
                return TlsGatewayConnection(InetSocketAddress(loopback, port), bytes.copyOf(), connectBudget,
                    readyBudget, prepare, { true }, { factory().also { channels.add(it) } }).also {
                    frames.add(it.frame.duplicate())
                }
            }
            override fun close() = Unit
        }
        val connector = SocksNioGatewayConnect(gateway, { readyAction(it); results.add(it) }, errors::add, replyBudget, io)
        val server = SocksNioServer(SocksNioHandshake({ credentials }, { entry ->
            entries.add(entry); admitted(entry, connector)
        }, clientIo), config = config, sessionNanoClock = clock).also { it.start() }

        fun client(payload: ByteArray = byteArrayOf()): Socket = Socket().also {
            it.soTimeout = 3000
            it.connect(InetSocketAddress(loopback, server.stats().port!!))
            it.getOutputStream().write(handshake + SocksProtocol.encodeRequest(SocksRequest(1, SocksDestination.Ip(loopback), 443)) + payload)
            assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(it, 4))
        }
        fun entry(): SocksNioHandshake.AdmittedRequest { await { entries.isNotEmpty() }; return checkNotNull(entries.peek()) }
        fun ready(): SocksNioGatewayConnect.Ready { await { results.isNotEmpty() }; return checkNotNull(results.poll()) }
        fun owner(entry: SocksNioHandshake.AdmittedRequest, action: (SocksNioHandshake.AdmittedRequest) -> Unit) {
            val done = CountDownLatch(1)
            val error = AtomicReference<Throwable>()
            assertEquals(SocksEventLoop.Submission.ACCEPTED, entry.session.owner.submit {
                try { action(entry) } catch (caught: Throwable) { error.set(caught) } finally { done.countDown() }
            })
            assertTrue(done.await(3, TimeUnit.SECONDS))
            error.get()?.let { throw it }
        }
        fun assertReleased() {
            await { server.stats().admission!!.tcp.current == 0 }
            assertTrue(channels.none { it.isOpen })
            assertTrue(frames.all(::wiped))
            entries.forEach { entry -> owner(entry) {
                assertEquals(SocksSession.State.CLOSED, it.session.snapshot().state)
                assertEquals(0, it.session.snapshot().bufferBytes)
                assertEquals(0, it.session.snapshot().buffers)
            } }
        }
        fun stopAndAssert() {
            assertTrue(server.stop())
            val stats = server.stats()
            assertEquals(SocksNioServer.State.STOPPED, stats.state)
            assertEquals(0, stats.admission!!.handshakes.current)
            assertEquals(0, stats.admission.tcp.current)
            assertEquals(0, stats.admission.udp.current)
            assertEquals(listOf(0, 0), stats.admission.ownerLoads)
            stats.loops.forEach {
                assertEquals(0, it.channels); assertEquals(0, it.keys); assertEquals(0, it.resources)
                assertEquals(0, it.timers); assertEquals(0L, it.cleanupFailures)
            }
            assertTrue(channels.none { it.isOpen })
            assertTrue(frames.all(::wiped))
        }
        override fun close() = stopAndAssert()
    }

    private fun pendingConnect(calls: AtomicInteger) = object : SocksNioGatewayConnect.GatewayIo {
        override fun finishConnect(channel: SocketChannel): Boolean { calls.incrementAndGet(); return false }
    }
    private fun gateway(action: (ServerSocket) -> Unit) {
        ServerSocket(0, 32, loopback).use { it.soTimeout = 3000; action(it) }
    }
    private fun frame(bytes: ByteArray): ByteArray = ByteBuffer.allocate(8 + bytes.size)
        .putInt(TlsGatewayChannel.FRAME_MAGIC_INT).putInt(bytes.size).put(bytes).array()
    private fun replyFrame(json: String) = frame(json.toByteArray(Charsets.UTF_8))
    private fun assertFailure(socket: Socket, code: Int = SocksProtocol.REPLY_GENERAL_FAILURE) {
        assertArrayEquals(SocksProtocol.encodeReply(code), read(socket, 10))
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
    private fun assertNoData(socket: Socket) {
        val old = socket.soTimeout
        socket.soTimeout = 80
        try { assertThrows(SocketTimeoutException::class.java) { socket.getInputStream().read() } }
        finally { socket.soTimeout = old }
    }
    private fun limited(buffer: ByteBuffer, count: Int, operation: (ByteBuffer) -> Int): Int {
        val old = buffer.limit()
        buffer.limit(buffer.position() + minOf(count, buffer.remaining()))
        return try { operation(buffer) } finally { buffer.limit(old) }
    }
    private fun wiped(buffer: ByteBuffer): Boolean {
        val copy = buffer.duplicate().also { it.clear() }
        while (copy.hasRemaining()) if (copy.get() != 0.toByte()) return false
        return true
    }
    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (!condition()) {
            assertTrue("condition deadline", System.nanoTime() < deadline)
            Thread.sleep(2)
        }
    }
}
