package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.SocksUdpRequest
import com.example.layanalyzer.capture.TlsInterceptionPolicy
import com.example.layanalyzer.capture.UdpDestinationPolicy
import com.example.layanalyzer.model.QuicPolicy
import com.example.layanalyzer.model.TlsCaptureSettings
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class UdpPacketPolicyTest {
    private val loopback = ip(127, 0, 0, 1)
    private val ipv6 = InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 })
    private val client = InetSocketAddress(loopback, 40000)
    private val target = InetSocketAddress(loopback, 53)
    private val payload = byteArrayOf(1, 2, 3)
    private val blockedPolicy = TlsInterceptionPolicy.udpPolicy(
        TlsCaptureSettings(enabled = true, quicPolicy = QuicPolicy.BlockSelectedUdp443))

    @Test fun malformedFirstPacketDoesNotLockClientOrRefreshIdle() = withPolicy { f, p ->
        val original = p.activity()
        f.now.addAndGet(100)
        assertDrop(UdpPacketPolicy.DropReason.INVALID, p.fromClient(client, byteArrayOf(0, 0, 0)))
        assertNull(p.stats().clientEndpoint)
        assertEquals(original, p.activity())
        val other = InetSocketAddress(loopback, 40001)
        assertTrue(p.fromClient(other, request()) is UdpPacketPolicy.Send)
        assertEquals(other, p.stats().clientEndpoint)
    }

    @Test fun onlyResolvedLoopbackAndFirstValidAddressAndPortAreAccepted() = withPolicy { _, p ->
        listOf(InetSocketAddress(ip(192, 0, 2, 1), 40000),
            InetSocketAddress.createUnresolved("localhost", 40000), InetSocketAddress(loopback, 0)).forEach {
            assertDrop(UdpPacketPolicy.DropReason.SOURCE, p.fromClient(it, request()))
        }
        assertNull(p.stats().clientEndpoint)
        p.fromClient(client, request())
        val activity = p.activity()
        listOf(InetSocketAddress(loopback, 40001), InetSocketAddress(ip(127, 0, 0, 2), 40000)).forEach {
            assertDrop(UdpPacketPolicy.DropReason.SOURCE, p.fromClient(it, request(port = 443)))
        }
        assertEquals(activity, p.activity())
        assertEquals(5L, p.stats().sourceRejectedDatagrams)
    }

    @Test fun rejectsEveryTruncatedIpHeaderFragmentReservedByteAndUnknownAddress() = withPolicy { _, p ->
        listOf(loopback, ipv6).forEach { address ->
            val wire = request(address = address, bytes = byteArrayOf())
            (0 until wire.size).forEach { length ->
                assertDrop(UdpPacketPolicy.DropReason.INVALID, p.fromClient(client, wire, length = length))
            }
        }
        listOf(0, 1, 2, 3).forEach { index ->
            val wire = request().also { it[index] = 9 }
            assertDrop(UdpPacketPolicy.DropReason.INVALID, p.fromClient(client, wire))
        }
        assertNull(p.stats().clientEndpoint)
    }

    @Test fun rejectsEmptyAndTruncatedDomainAndZeroPortAndBadSlices() = withPolicy { _, p ->
        val bad = listOf(byteArrayOf(0, 0, 0, 3, 0, 0, 53), byteArrayOf(0, 0, 0, 3, 4, 65, 0, 53),
            request(port = 0))
        bad.forEach { assertDrop(UdpPacketPolicy.DropReason.INVALID, p.fromClient(client, it)) }
        assertDrop(UdpPacketPolicy.DropReason.INVALID, p.fromClient(client, request(), -1))
        assertDrop(UdpPacketPolicy.DropReason.INVALID, p.fromClient(client, request(), length = 500))
        assertNull(p.stats().clientEndpoint)
        assertTrue(p.activity().dnsOnly)
    }

    @Test fun ipv4AndIpv6RequestsAndResponsesPreservePayloadPortAndFamily() = withPolicy { _, p ->
        listOf(loopback, ipv6).forEach { address ->
            val send = p.fromClient(client, request(address = address, port = 65535)) as UdpPacketPolicy.Send
            assertEquals(InetSocketAddress(address, 65535), send.target)
            assertArrayEquals(payload, send.bytes)
            p.complete(send, UdpPacketPolicy.Completion.SENT)
            val response = p.fromUpstream(send.target, payload) as UdpPacketPolicy.Send
            assertEquals(client, response.target)
            assertEquals(UdpPacketPolicy.Direction.CLIENT, response.direction)
            val decoded = checkNotNull(SocksProtocol.decodeUdpRequest(response.bytes))
            assertEquals(SocksDestination.Ip(address), decoded.destination)
            assertEquals(65535, decoded.port)
            assertArrayEquals(payload, decoded.payload)
        }
    }

    @Test fun copiesOnlyThePayloadSliceAndDoesNotRetainScratch() = withPolicy { _, p ->
        val scratch = byteArrayOf(99) + request() + byteArrayOf(98)
        val send = p.fromClient(client, scratch, 1, scratch.size - 2) as UdpPacketPolicy.Send
        scratch.fill(0)
        assertArrayEquals(payload, send.bytes)
        p.complete(send, UdpPacketPolicy.Completion.SENT)
        val responseScratch = byteArrayOf(99) + payload + byteArrayOf(98)
        val response = p.fromUpstream(target, responseScratch, 1, payload.size) as UdpPacketPolicy.Send
        responseScratch.fill(0)
        assertArrayEquals(payload, SocksProtocol.decodeUdpRequest(response.bytes)!!.payload)
        assertEquals(payload.size + 10, response.bytes.size)
    }

    @Test fun zeroLengthDatagramsHaveExplicitSuccessfulCompletion() = withPolicy { _, p ->
        val send = p.fromClient(client, request(bytes = byteArrayOf())) as UdpPacketPolicy.Send
        assertEquals(0, send.bytes.size)
        assertEquals(0, p.stats().allowedPeers)
        assertTrue(p.complete(send, UdpPacketPolicy.Completion.SENT))
        assertEquals(1, p.stats().allowedPeers)
        assertEquals(0L, p.stats().sentBytes)
        val response = p.fromUpstream(target, byteArrayOf()) as UdpPacketPolicy.Send
        assertEquals(10, response.bytes.size)
        assertArrayEquals(byteArrayOf(), SocksProtocol.decodeUdpRequest(response.bytes)!!.payload)
    }

    @Test fun largePayloadsAndResponseHeaderBudgetKeepTheSystemSizeBoundary() = withPolicy { _, p ->
        listOf(loopback, ipv6).forEach { address ->
            val bytes = ByteArray(minOf(UdpPacketPolicy.maxPayloadBytes(address), 65535 - 6 - address.address.size)) { it.toByte() }
            val send = p.fromClient(client, request(address = address, bytes = bytes)) as UdpPacketPolicy.Send
            assertArrayEquals(bytes, send.bytes)
            p.complete(send, UdpPacketPolicy.Completion.SENT)
            val responsePayload = ByteArray(65507 - 6 - address.address.size) { (it * 13).toByte() }
            val response = p.fromUpstream(send.target, responsePayload) as UdpPacketPolicy.Send
            assertEquals(65507, response.bytes.size)
            assertArrayEquals(responsePayload, SocksProtocol.decodeUdpRequest(response.bytes)!!.payload)
            assertDrop(UdpPacketPolicy.DropReason.TOO_LARGE,
                p.fromUpstream(send.target, responsePayload + byteArrayOf(0)))
        }
    }

    @Test fun oversizedFramesAndPayloadsDropWithoutAllocatingPendingActions() = withPolicy { _, p ->
        val activity = p.activity()
        assertDrop(UdpPacketPolicy.DropReason.TOO_LARGE,
            p.fromClient(client, ByteArray(UdpPacketPolicy.MAX_RECEIVE_BYTES + 1)))
        assertNull(p.stats().clientEndpoint)
        assertDrop(UdpPacketPolicy.DropReason.TOO_LARGE,
            p.fromClient(client, request(bytes = ByteArray(65508))))
        assertNull(p.stats().clientEndpoint)
        assertEquals(activity, p.activity())
        assertEquals(0, p.stats().allowedPeers)
    }

    @Test fun domainReturnsPendingActionWithoutResolutionOrEarlyPolicyEvaluation() {
        val decisions = AtomicLong()
        val rule = UdpDestinationPolicy { address, port -> decisions.incrementAndGet(); blockedPolicy.decide(address, port) }
        withPolicy(rule) { f, p ->
            val pending = p.fromClient(client, domainRequest("udp.example.invalid", 443)) as UdpPacketPolicy.Resolve
            assertEquals("udp.example.invalid", pending.name)
            assertArrayEquals(payload, pending.bytes)
            assertEquals(0L, decisions.get())
            val activity = p.activity()
            f.now.addAndGet(100)
            assertDrop(UdpPacketPolicy.DropReason.POLICY, p.resolved(pending, ipv6))
            assertEquals(1L, decisions.get())
            assertEquals(activity, p.activity())
            assertEquals(1L, p.stats().intervention.blockedDatagrams)
            assertEquals(0, p.stats().allowedPeers)
            assertDrop(UdpPacketPolicy.DropReason.INACTIVE, p.resolved(pending, ipv6))
        }
    }

    @Test fun domainResolutionSharesTheOwnedArrayAndCanFinishOnlyOnce() = withPolicy { _, p ->
        val pending = p.fromClient(client, domainRequest("fixture.invalid", 53)) as UdpPacketPolicy.Resolve
        val send = p.resolved(pending, loopback) as UdpPacketPolicy.Send
        assertSame(pending.bytes, send.bytes)
        assertFalse(p.complete(pending, UdpPacketPolicy.Completion.QUEUE_DROPPED))
        assertTrue(p.complete(send, UdpPacketPolicy.Completion.SENT))
        assertFalse(p.complete(send, UdpPacketPolicy.Completion.SENT))
        assertEquals(payload.size.toLong(), p.stats().sentBytes)
    }

    @Test fun preserveDefaultForwards443ForBothFamilies() = withPolicy { _, p ->
        listOf(loopback, ipv6).forEach { assertTrue(p.fromClient(client, request(it, 443)) is UdpPacketPolicy.Send) }
        assertEquals(0L, p.stats().intervention.blockedDatagrams)
    }

    @Test fun frozenBlockedPolicyOnlyDrops443AndNeverAllowsItsSpoofedResponse() {
        var settings = TlsCaptureSettings(enabled = true, quicPolicy = QuicPolicy.BlockSelectedUdp443)
        val frozen = TlsInterceptionPolicy.udpPolicy(settings)
        settings = settings.copy(quicPolicy = QuicPolicy.Preserve)
        assertEquals(QuicPolicy.Preserve, settings.quicPolicy)
        withPolicy(frozen) { _, p ->
            listOf(loopback, ipv6).forEach { address ->
                assertDrop(UdpPacketPolicy.DropReason.POLICY, p.fromClient(client, request(address, 443)))
                assertDrop(UdpPacketPolicy.DropReason.UNALLOWED_PEER,
                    p.fromUpstream(InetSocketAddress(address, 443), payload))
                listOf(53, 8443).forEach { assertTrue(p.fromClient(client, request(address, it)) is UdpPacketPolicy.Send) }
            }
            assertEquals(2L, p.stats().intervention.blockedDatagrams)
            assertEquals(6L, p.stats().intervention.blockedBytes)
            assertEquals(0L, p.stats().sentBytes)
        }
    }

    @Test fun responseRequiresExactSuccessfullySentAddressAndPort() = withPolicy { _, p ->
        val send = p.fromClient(client, request()) as UdpPacketPolicy.Send
        assertDrop(UdpPacketPolicy.DropReason.UNALLOWED_PEER, p.fromUpstream(target, payload))
        p.complete(send, UdpPacketPolicy.Completion.SENT)
        listOf(InetSocketAddress(loopback, 54), InetSocketAddress(ip(127, 0, 0, 2), 53)).forEach {
            assertDrop(UdpPacketPolicy.DropReason.UNALLOWED_PEER, p.fromUpstream(it, payload))
        }
        assertTrue(p.fromUpstream(target, payload) is UdpPacketPolicy.Send)
    }

    @Test fun peerTtlIncludesExactBoundaryAndSuccessfulResponsesRefreshIt() = withPolicy { f, p ->
        p.complete(p.fromClient(client, request()) as UdpPacketPolicy.Send, UdpPacketPolicy.Completion.SENT)
        f.now.addAndGet(UdpPacketPolicy.PEER_TTL_NANOS)
        assertTrue(p.fromUpstream(target, payload) is UdpPacketPolicy.Send)
        f.now.addAndGet(UdpPacketPolicy.PEER_TTL_NANOS)
        assertTrue(p.fromUpstream(target, payload) is UdpPacketPolicy.Send)
        val activity = p.activity()
        f.now.addAndGet(UdpPacketPolicy.PEER_TTL_NANOS + 1)
        assertDrop(UdpPacketPolicy.DropReason.UNALLOWED_PEER, p.fromUpstream(target, payload))
        assertEquals(activity, p.activity())
        assertEquals(0, p.stats().allowedPeers)
    }

    @Test fun peerExpiryUsesElapsedMonotonicTimeAcrossNanoTimeWrap() = withPolicy { f, p ->
        f.now.set(Long.MAX_VALUE - 20)
        p.complete(p.fromClient(client, request()) as UdpPacketPolicy.Send, UdpPacketPolicy.Completion.SENT)
        f.now.addAndGet(UdpPacketPolicy.PEER_TTL_NANOS + 1)
        assertDrop(UdpPacketPolicy.DropReason.UNALLOWED_PEER, p.fromUpstream(target, payload))
    }

    @Test fun allowedListCapsAt512AndEvictsLeastRecentlyUsedPeer() = withPolicy { f, p ->
        fun sent(port: Int) {
            f.now.incrementAndGet()
            p.complete(p.fromClient(client, request(port = port)) as UdpPacketPolicy.Send, UdpPacketPolicy.Completion.SENT)
        }
        (1..512).forEach(::sent)
        p.fromUpstream(InetSocketAddress(loopback, 1), payload)
        sent(513)
        assertEquals(512, p.stats().allowedPeers)
        assertDrop(UdpPacketPolicy.DropReason.UNALLOWED_PEER, p.fromUpstream(InetSocketAddress(loopback, 2), payload))
        assertTrue(p.fromUpstream(InetSocketAddress(loopback, 1), payload) is UdpPacketPolicy.Send)
        assertTrue(p.fromUpstream(InetSocketAddress(loopback, 513), payload) is UdpPacketPolicy.Send)
    }

    @Test fun newSuccessfulSendPrunesExpiredPeersAndRefreshesItsTarget() = withPolicy { f, p ->
        p.complete(p.fromClient(client, request()) as UdpPacketPolicy.Send, UdpPacketPolicy.Completion.SENT)
        f.now.addAndGet(UdpPacketPolicy.PEER_TTL_NANOS + 1)
        p.complete(p.fromClient(client, request(port = 123)) as UdpPacketPolicy.Send, UdpPacketPolicy.Completion.SENT)
        assertEquals(1, p.stats().allowedPeers)
        assertDrop(UdpPacketPolicy.DropReason.UNALLOWED_PEER, p.fromUpstream(target, payload))
    }

    @Test fun oversizedResponseDoesNotRenewPeerOrIdleAndCancelledPacketDoesNotAllowPeer() = withPolicy { f, p ->
        p.complete(p.fromClient(client, request()) as UdpPacketPolicy.Send, UdpPacketPolicy.Completion.SENT)
        val activity = p.activity()
        f.now.addAndGet(UdpPacketPolicy.PEER_TTL_NANOS)
        assertDrop(UdpPacketPolicy.DropReason.TOO_LARGE, p.fromUpstream(target, ByteArray(65507)))
        assertEquals(activity, p.activity())
        f.now.incrementAndGet()
        assertDrop(UdpPacketPolicy.DropReason.UNALLOWED_PEER, p.fromUpstream(target, payload))
        val pending = p.fromClient(client, request()) as UdpPacketPolicy.Send
        assertTrue(p.complete(pending, UdpPacketPolicy.Completion.CANCELLED))
        assertFalse(p.complete(pending, UdpPacketPolicy.Completion.SENT))
        assertEquals(0, p.stats().allowedPeers)
        assertEquals(0L, p.stats().queueDroppedDatagrams)
    }

    @Test fun successfulSendRenewsPeerButQueueCompletionDoesNotRenewAssociationIdle() = withPolicy { f, p ->
        val pending = p.fromClient(client, request()) as UdpPacketPolicy.Send
        val activity = p.activity()
        f.now.addAndGet(1000)
        p.complete(pending, UdpPacketPolicy.Completion.SENT)
        assertEquals(activity, p.activity())
        f.now.addAndGet(UdpPacketPolicy.PEER_TTL_NANOS)
        assertTrue(p.fromUpstream(target, payload) is UdpPacketPolicy.Send)
    }

    @Test fun queueDropSendFailureAndDnsFailureAreDistinctAndDoNotAllowPeers() = withPolicy(blockedPolicy) { _, p ->
        p.fromClient(client, request(port = 443))
        p.fromClient(client, byteArrayOf(0))
        val queued = p.fromClient(client, request()) as UdpPacketPolicy.Send
        p.complete(queued, UdpPacketPolicy.Completion.QUEUE_DROPPED)
        assertFalse(p.complete(queued, UdpPacketPolicy.Completion.SEND_FAILED))
        p.complete(p.fromClient(client, request()) as UdpPacketPolicy.Send, UdpPacketPolicy.Completion.SEND_FAILED)
        p.complete(p.fromClient(client, domainRequest("bad.invalid", 53)) as UdpPacketPolicy.Resolve,
            UdpPacketPolicy.Completion.RESOLUTION_FAILED)
        val stats = p.stats()
        assertEquals(1L, stats.intervention.blockedDatagrams)
        assertEquals(1L, stats.invalidDatagrams)
        assertEquals(1L, stats.queueDroppedDatagrams)
        assertEquals(3L, stats.queueDroppedBytes)
        assertEquals(1L, stats.sendFailures)
        assertEquals(1L, stats.resolutionFailures)
        assertEquals(0, stats.allowedPeers)
        assertEquals(0L, stats.sentBytes)
    }

    @Test fun responseQueueDropChargesItsHeaderAndCannotIncrementPolicyOrSendFailures() = withPolicy { _, p ->
        p.complete(p.fromClient(client, request()) as UdpPacketPolicy.Send, UdpPacketPolicy.Completion.SENT)
        val response = p.fromUpstream(target, payload) as UdpPacketPolicy.Send
        p.complete(response, UdpPacketPolicy.Completion.QUEUE_DROPPED)
        assertEquals(13L, p.stats().queueDroppedBytes)
        assertEquals(3L, p.stats().receivedBytes)
        assertEquals(0L, p.stats().sendFailures)
        assertEquals(0L, p.stats().intervention.blockedDatagrams)
    }

    @Test fun onlyValidUdpUpdatesActivityAndNonDnsTransitionIsPermanent() = withPolicy(blockedPolicy) { f, p ->
        assertTrue(p.activity().dnsOnly)
        f.now.addAndGet(10)
        p.fromClient(client, request())
        assertEquals(f.now.get(), p.activity().lastActivityNanos)
        assertTrue(p.activity().dnsOnly)
        f.now.addAndGet(10)
        p.fromClient(client, request(port = 443))
        assertFalse(p.activity().dnsOnly) // A legal policy-blocked request matches legacy idle semantics.
        f.now.addAndGet(10)
        p.fromClient(client, domainRequest("dns.invalid", 53))
        assertFalse(p.activity().dnsOnly)
        val accepted = p.activity()
        f.now.addAndGet(10)
        p.fromClient(InetSocketAddress(loopback, 40001), request())
        p.fromClient(client, byteArrayOf(0))
        p.fromUpstream(target, payload)
        assertEquals(accepted, p.activity())
    }

    @Test fun closeClearsPeersAndEndpointAndLateResolutionAndCompletionAreHarmless() = withPolicy { _, p ->
        val queued = p.fromClient(client, request()) as UdpPacketPolicy.Send
        val pending = p.fromClient(client, domainRequest("late.invalid", 53)) as UdpPacketPolicy.Resolve
        p.complete(p.fromClient(client, request()) as UdpPacketPolicy.Send, UdpPacketPolicy.Completion.SENT)
        p.close()
        p.close()
        assertEquals(0, p.stats().allowedPeers)
        assertNull(p.stats().clientEndpoint)
        val before = p.stats()
        assertDrop(UdpPacketPolicy.DropReason.INACTIVE, p.resolved(pending, loopback))
        assertDrop(UdpPacketPolicy.DropReason.INACTIVE, p.fromClient(client, request()))
        assertFalse(p.complete(queued, UdpPacketPolicy.Completion.SENT))
        assertEquals(before, p.stats())
    }

    @Test fun ownerCheckRejectsForeignThreadAndControlBytesNeverChangeUdpActivity() {
        Fixture().use { f ->
            assertThrows(IllegalStateException::class.java) { f.policy.activity() }
            val original = AtomicReference<UdpPacketPolicy.Activity>()
            f.owner { original.set(f.policy.activity()) }
            f.now.addAndGet(10)
            f.control.getOutputStream().write(ByteArray(2048) { 19 })
            f.owner { assertEquals(original.get(), f.policy.activity()) }
            f.control.shutdownOutput()
            assertEquals(-1, f.control.getInputStream().read())
            f.owner {
                assertTrue(f.policy.stats().closed)
                assertEquals(0, f.policy.stats().allowedPeers)
                assertEquals(original.get(), f.policy.activity())
            }
        }
    }

    @Test fun realSelectorRoundTripPreservesLargeDatagramAndDropsOtherClientAndForgedPeer() {
        Fixture(driveWire = true).use { f ->
            DatagramSocket(0, loopback).use { clientSocket -> DatagramSocket(0, loopback).use { upstream ->
                DatagramSocket(0, loopback).use { attacker ->
                    clientSocket.soTimeout = 3000
                    upstream.soTimeout = 3000
                    val large = ByteArray(60_000) { (it * 17).toByte() }
                    // Malformed traffic cannot claim the endpoint before the real client.
                    send(attacker, f.relayPort, byteArrayOf(0))
                    send(clientSocket, f.relayPort, request(port = upstream.localPort, bytes = large))
                    val heard = receive(upstream)
                    assertArrayEquals(large, heard.data.copyOf(heard.length))
                    // A different client cannot forward even to a permitted target.
                    send(attacker, f.relayPort, request(port = upstream.localPort, bytes = byteArrayOf(9)))
                    send(attacker, heard.port, byteArrayOf(8))
                    f.awaitStats { it.sourceRejectedDatagrams == 1L && it.unallowedResponses == 1L }
                    upstream.send(DatagramPacket(large, large.size, heard.address, heard.port))
                    val reply = receive(clientSocket)
                    assertArrayEquals(large, SocksProtocol.decodeUdpRequest(reply.data, length = reply.length)!!.payload)
                    upstream.soTimeout = 100
                    assertThrows(SocketTimeoutException::class.java) { receive(upstream) }
                    f.owner {
                        assertEquals(1L, f.policy.stats().sourceRejectedDatagrams)
                        assertEquals(1L, f.policy.stats().unallowedResponses)
                        assertEquals(60000L, f.policy.stats().sentBytes)
                        assertEquals(60000L, f.policy.stats().receivedBytes)
                    }
                }
            } }
        }
    }

    @Test fun realFrozenPolicyBlocks443AndPreserveDeliversToTheSameSocket() {
        val address = ip(127, 0, 0, 10)
        DatagramSocket(InetSocketAddress(address, 443)).use { receiver ->
            receiver.soTimeout = 3000
            Fixture(driveWire = true).use { f -> DatagramSocket(0, loopback).use { sender ->
                send(sender, f.relayPort, request(address, 443))
                assertArrayEquals(payload, receive(receiver).let { it.data.copyOf(it.length) })
            } }
            Fixture(blockedPolicy, driveWire = true).use { f -> DatagramSocket(0, loopback).use { sender ->
                send(sender, f.relayPort, request(address, 443))
                assertTrue(f.packetSeen.await(3, TimeUnit.SECONDS))
                f.owner {
                    assertEquals(1L, f.policy.stats().intervention.blockedDatagrams)
                    assertEquals(0L, f.policy.stats().sentBytes)
                    assertEquals(0, f.policy.stats().allowedPeers)
                }
                receiver.soTimeout = 100
                assertThrows(SocketTimeoutException::class.java) { receive(receiver) }
            } }
        }
    }

    private fun withPolicy(rule: UdpDestinationPolicy = UdpDestinationPolicy.PRESERVE, body: (Fixture, UdpPacketPolicy) -> Unit) {
        Fixture(rule).use { f -> f.owner { body(f, f.policy) } }
    }

    /** Real NIO-401 lifecycle; optional single-packet I/O here is a fixture, not a production queue. */
    private inner class Fixture(rule: UdpDestinationPolicy = UdpDestinationPolicy.PRESERVE, driveWire: Boolean = false) : AutoCloseable {
        val now = AtomicLong(1000)
        val packetSeen = CountDownLatch(1)
        val activated = CountDownLatch(1)
        val failure = AtomicReference<Throwable>()
        lateinit var active: UdpAssociation.Active
        lateinit var policy: UdpPacketPolicy
        val association = UdpAssociation({}, { established ->
            active = established
            policy = UdpPacketPolicy(active.session, rule)
            active.ownDataPlane(policy)
            if (driveWire) {
                val scratch = ByteBuffer.allocate(UdpPacketPolicy.MAX_RECEIVE_BYTES)
                listOf(active.relay, active.upstream).forEach { registration ->
                    registration.replaceHandler { _, _ ->
                        try {
                            scratch.clear()
                            val source = (registration.channel as DatagramChannel).receive(scratch) as? InetSocketAddress
                            if (source != null) {
                                val decision = if (registration === active.relay)
                                    policy.fromClient(source, scratch.array(), length = scratch.position())
                                else policy.fromUpstream(source, scratch.array(), length = scratch.position())
                                if (decision is UdpPacketPolicy.Send) {
                                    val destination = if (decision.direction == UdpPacketPolicy.Direction.UPSTREAM) active.upstream else active.relay
                                    val sent = (destination.channel as DatagramChannel).send(ByteBuffer.wrap(decision.bytes), decision.target)
                                    assertEquals("fixture does not simulate congestion", decision.bytes.size, sent)
                                    policy.complete(decision, UdpPacketPolicy.Completion.SENT)
                                }
                                packetSeen.countDown()
                            }
                        } catch (error: Throwable) { failure.set(error); active.close(error) }
                    }
                    registration.interestOps(SelectionKey.OP_READ)
                }
            }
            activated.countDown()
        })
        val credentials = SocksCredentials.of("User", "Password")
        val server = SocksNioServer(SocksNioHandshake({ credentials }, association::start), sessionNanoClock = now::get).also { it.start() }
        val control = Socket(loopback, server.stats().port!!).also { socket ->
            socket.soTimeout = 3000
            socket.getOutputStream().write(byteArrayOf(5, 1, 2, 1, 4) + "User".toByteArray() + byteArrayOf(8) +
                "Password".toByteArray() + SocksProtocol.encodeRequest(SocksRequest(3, SocksDestination.Ip(loopback), 0)))
            val reply = ByteArray(14)
            java.io.DataInputStream(socket.getInputStream()).readFully(reply)
            assertArrayEquals(byteArrayOf(5, 2, 1, 0, 5, 0, 0, 1), reply.copyOf(8))
            assertTrue(activated.await(3, TimeUnit.SECONDS))
        }
        val relayPort: Int get() = ((active.relay.channel as DatagramChannel).localAddress as InetSocketAddress).port

        fun owner(action: () -> Unit) {
            val done = CountDownLatch(1)
            val caught = AtomicReference<Throwable>()
            assertEquals(SocksEventLoop.Submission.ACCEPTED, active.session.owner.submit {
                try { action() } catch (error: Throwable) { caught.set(error) } finally { done.countDown() }
            })
            assertTrue(done.await(3, TimeUnit.SECONDS))
            caught.get()?.let { throw it }
            failure.get()?.let { throw it }
        }

        fun awaitStats(predicate: (UdpPacketPolicy.Stats) -> Boolean) {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
            while (true) {
                var matched = false
                owner { matched = predicate(policy.stats()) }
                if (matched) return
                assertTrue("packet processing deadline", System.nanoTime() < deadline)
                Thread.sleep(2)
            }
        }

        override fun close() {
            control.close()
            assertTrue(server.stop())
            failure.get()?.let { throw it }
            assertEquals(0, server.stats().admission!!.udp.current)
            server.stats().loops.forEach {
                assertEquals(0, it.channels)
                assertEquals(0, it.keys)
                assertEquals(0, it.resources)
                assertEquals(0, it.timers)
                assertEquals(0L, it.callbackFailures)
                assertEquals(0L, it.cleanupFailures)
            }
        }
    }

    private fun request(address: InetAddress = loopback, port: Int = 53, bytes: ByteArray = payload) =
        SocksProtocol.encodeUdpRequest(SocksUdpRequest(SocksDestination.Ip(address), port, bytes))
    private fun domainRequest(name: String, port: Int) =
        SocksProtocol.encodeUdpRequest(SocksUdpRequest(SocksDestination.Domain(name), port, payload))
    private fun assertDrop(reason: UdpPacketPolicy.DropReason, actual: UdpPacketPolicy.Decision) =
        assertEquals(UdpPacketPolicy.Dropped(reason), actual)
    private fun ip(vararg bytes: Int): InetAddress = InetAddress.getByAddress(bytes.map { it.toByte() }.toByteArray())
    private fun send(socket: DatagramSocket, port: Int, bytes: ByteArray) = socket.send(DatagramPacket(bytes, bytes.size, loopback, port))
    private fun receive(socket: DatagramSocket): DatagramPacket = DatagramPacket(ByteArray(65535), 65535).also(socket::receive)
}
