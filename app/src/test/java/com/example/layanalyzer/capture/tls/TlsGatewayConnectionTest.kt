package com.example.layanalyzer.capture.tls

import com.example.layanalyzer.model.TlsCaptureSettings
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Native-channel ownership/metadata tests; NIO READY and relay are deliberately the next stage. */
class TlsGatewayConnectionTest {
    private val loopback = InetAddress.getByName("127.0.0.1")
    private val destination = InetAddress.getByName("198.51.100.7")
    private val token = "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU"
    private val policy = TlsRoutingPolicy.freeze(TlsCaptureSettings(enabled = true, candidatePorts = setOf(443)))

    private fun gateway(port: Int = 12345, prepare: (Socket) -> Unit = {},
        factory: () -> SocketChannel = { SocketChannel.open() },
        ids: () -> String = { "connection-301" }, tokenBytes: ByteArray = token.toByteArray(),
        readyMillis: Int = 11_000) = TlsGatewayChannel(port, tokenBytes, "capture-301", 7,
        policy, prepare, readyMillis, ids, factory)

    private fun content(buffer: ByteBuffer): ByteArray = buffer.duplicate().apply { clear() }.let {
        ByteArray(it.remaining()).also(it::get)
    }

    private fun metadata(description: TlsGatewayConnection): JSONObject {
        val buffer = description.frame.duplicate()
        assertEquals(0x4c415431, buffer.int)
        val length = buffer.int
        assertEquals(length, buffer.remaining())
        return JSONObject(String(ByteArray(length).also(buffer::get), Charsets.UTF_8))
    }

    @Test fun `route and description construct only metadata before any socket exists`() {
        val creations = AtomicInteger()
        val preparations = AtomicInteger()
        gateway(factory = { creations.incrementAndGet(); SocketChannel.open() },
            prepare = { preparations.incrementAndGet() }).use { gateway ->
            assertEquals(SocksNioTlsGateway.Route.GATEWAY, gateway.route(443))
            assertEquals(SocksNioTlsGateway.Route.DIRECT, gateway.route(80))
            gateway.describe(destination, 443).use { description ->
                val body = metadata(description)
                assertEquals(setOf("version", "captureId", "connectionId", "networkGeneration",
                    "destinationAddress", "destinationPort", "token"), body.keySet())
                assertEquals(1, body.getInt("version"))
                assertEquals("capture-301", body.getString("captureId"))
                assertEquals("connection-301", body.getString("connectionId"))
                assertEquals(7, body.getLong("networkGeneration"))
                assertEquals("198.51.100.7", body.getString("destinationAddress"))
                assertEquals(443, body.getInt("destinationPort"))
                assertEquals(token, body.getString("token"))
                assertEquals(InetSocketAddress(loopback, 12345), description.endpoint)
                assertEquals(1_000_000_000L, description.connectTimeoutNanos)
                assertEquals(11_000_000_000L, description.readyTimeoutNanos)
                assertTrue(description.frame.isReadOnly)
                assertFalse(description.toString().contains(token))
            }
            assertEquals(0, creations.get())
            assertEquals(0, preparations.get())
        }
    }

    @Test fun `hop is native unconnected nonblocking and can register on the owner selector`() {
        ServerSocketChannel.open().use { listener ->
            listener.bind(InetSocketAddress(loopback, 0))
            listener.configureBlocking(false)
            var protected: Socket? = null
            gateway((listener.localAddress as InetSocketAddress).port, prepare = {
                assertFalse(it.isConnected)
                assertFalse(it.isBound)
                assertNotNull(it.channel)
                assertTrue(it.channel.isBlocking)
                protected = it
            }).use { gateway ->
                gateway.describe(destination, 443).use { description ->
                    description.openChannel().use { hop ->
                        assertSame(hop.socket(), protected)
                        assertSame(hop, protected!!.channel)
                        assertFalse(hop.isConnected)
                        assertFalse(hop.isConnectionPending)
                        assertFalse(hop.isBlocking)
                        assertNull(listener.accept())
                        Selector.open().use { selector ->
                            val connected = hop.connect(description.endpoint)
                            val key = hop.register(selector, if (connected) 0 else SelectionKey.OP_CONNECT)
                            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
                            while (!hop.isConnected && System.nanoTime() < deadline) {
                                selector.select(100)
                                selector.selectedKeys().clear()
                                if (hop.finishConnect()) key.interestOps(0)
                            }
                            assertTrue(hop.isConnected)
                            listener.accept().use { assertNotNull(it) }
                        }
                    }
                }
            }
        }
    }

    @Test fun `prepare refusal never connects and closes both channel and metadata`() {
        ServerSocketChannel.open().use { listener ->
            listener.bind(InetSocketAddress(loopback, 0))
            listener.configureBlocking(false)
            lateinit var created: SocketChannel
            gateway((listener.localAddress as InetSocketAddress).port,
                prepare = { throw IOException("protect refused") },
                factory = { SocketChannel.open().also { created = it } }).use { gateway ->
                val description = gateway.describe(destination, 443)
                val view = description.frame
                assertThrows(IOException::class.java) { description.openChannel() }
                assertFalse(created.isOpen)
                assertNull(listener.accept())
                assertTrue(content(view).all { it == 0.toByte() })
                assertThrows(IllegalStateException::class.java) { description.frame }
                description.close()
            }
        }
    }

    @Test fun `channel factory failure wipes metadata and cannot reopen`() {
        gateway(factory = { throw IOException("no channel") }).use { gateway ->
            val description = gateway.describe(destination, 443)
            val view = description.frame
            assertThrows(IOException::class.java) { description.openChannel() }
            assertTrue(content(view).all { it == 0.toByte() })
            assertThrows(IllegalStateException::class.java) { description.openChannel() }
        }
    }

    @Test fun `closed factory channel is rejected and metadata is wiped`() {
        val channel = SocketChannel.open().apply { close() }
        gateway(factory = { channel }).use { gateway ->
            val description = gateway.describe(destination, 443)
            val view = description.frame
            assertThrows(IllegalStateException::class.java) { description.openChannel() }
            assertTrue(content(view).all { it == 0.toByte() })
        }
    }

    @Test fun `prepare may not bind the loopback socket itself`() {
        lateinit var created: SocketChannel
        gateway(prepare = { it.bind(InetSocketAddress(loopback, 0)) },
            factory = { SocketChannel.open().also { created = it } }).use { gateway ->
            val description = gateway.describe(destination, 443)
            val view = description.frame
            assertThrows(IllegalStateException::class.java) { description.openChannel() }
            assertFalse(created.isOpen)
            assertTrue(content(view).all { it == 0.toByte() })
        }
    }

    @Test fun `description close wipes every view without closing the channel handed to owner`() {
        gateway().use { gateway ->
            val description = gateway.describe(destination, 443)
            val view = description.frame
            val duplicate = view.duplicate()
            description.openChannel().use { hop ->
                assertThrows(IllegalStateException::class.java) { description.openChannel() }
                description.close()
                description.close()
                assertTrue(hop.isOpen)
                assertTrue(content(view).all { it == 0.toByte() })
                assertTrue(content(duplicate).all { it == 0.toByte() })
                assertTrue(gateway.carriesTokenMaterial())
                assertThrows(IllegalStateException::class.java) { description.openChannel() }
            }
        }
    }

    @Test fun `unopened description can be cancelled without creating a channel`() {
        val creations = AtomicInteger()
        gateway(factory = { creations.incrementAndGet(); SocketChannel.open() }).use { gateway ->
            val description = gateway.describe(destination, 443)
            val view = description.frame
            description.close()
            assertTrue(content(view).all { it == 0.toByte() })
            assertThrows(IllegalStateException::class.java) { description.openChannel() }
            assertEquals(0, creations.get())
        }
    }

    @Test fun `run close between describe and open refuses instead of yielding a direct candidate`() {
        val creations = AtomicInteger()
        val gateway = gateway(factory = { creations.incrementAndGet(); SocketChannel.open() })
        val description = gateway.describe(destination, 443)
        val view = description.frame
        gateway.close()
        gateway.close()
        assertEquals(SocksNioTlsGateway.Route.UNAVAILABLE, gateway.route(443))
        assertEquals(SocksNioTlsGateway.Route.UNAVAILABLE, gateway.route(80))
        assertFalse(gateway.carriesTokenMaterial())
        assertThrows(IOException::class.java) { gateway.describe(destination, 443) }
        assertThrows(IOException::class.java) { description.openChannel() }
        assertEquals(0, creations.get())
        assertTrue(content(view).all { it == 0.toByte() })
    }

    @Test fun `run close during preparation refuses and closes created channel`() {
        lateinit var gateway: TlsGatewayChannel
        lateinit var created: SocketChannel
        gateway = gateway(prepare = { gateway.close() },
            factory = { SocketChannel.open().also { created = it } })
        val description = gateway.describe(destination, 443)
        val view = description.frame
        assertThrows(IOException::class.java) { description.openChannel() }
        assertFalse(created.isOpen)
        assertFalse(created.isConnected)
        assertTrue(content(view).all { it == 0.toByte() })
    }

    @Test fun `concurrent run close during metadata construction prevents publication`() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val result = CompletableFuture<Throwable>()
        val gateway = gateway(ids = { entered.countDown(); check(release.await(3, TimeUnit.SECONDS)); "id" })
        val worker = thread(isDaemon = true) {
            try { gateway.describe(destination, 443).use { error("published after close") } }
            catch (error: Throwable) { result.complete(error) }
        }
        try {
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            gateway.close()
            release.countDown()
            assertTrue(result.get(3, TimeUnit.SECONDS) is IOException)
            assertFalse(gateway.carriesTokenMaterial())
        } finally { release.countDown(); gateway.close(); worker.join(3_000) }
    }

    @Test fun `metadata failures and ports outside candidate scope never create channels`() {
        val creations = AtomicInteger()
        val factory = { creations.incrementAndGet(); SocketChannel.open() }
        gateway(factory = factory).use { gateway ->
            for (port in listOf(-1, 0, 65536, 80)) {
                assertThrows(IOException::class.java) { gateway.describe(destination, port) }
            }
            val scopedV6 = java.net.Inet6Address.getByAddress(null, ByteArray(16).apply { this[15] = 1 }, 2)
            assertThrows(IOException::class.java) { gateway.describe(scopedV6, 443) }
        }
        gateway(factory = factory, ids = { "invalid id" }).use { gateway ->
            assertThrows(IOException::class.java) { gateway.describe(destination, 443) }
        }
        assertEquals(0, creations.get())
    }

    @Test fun `IPv6 destinations stay literal and never determine the loopback endpoint`() {
        gateway().use { gateway ->
            val ipv6 = InetAddress.getByAddress(ByteArray(16).apply { this[15] = 1 })
            gateway.describe(ipv6, 443).use { description ->
                assertEquals(ipv6.hostAddress, metadata(description).getString("destinationAddress"))
                assertEquals(loopback, description.endpoint.address)
            }
        }
    }

    @Test fun `caller token changes do not corrupt metadata and run close does not wipe caller memory`() {
        val source = token.toByteArray()
        gateway(tokenBytes = source).use { gateway ->
            source.fill('X'.code.toByte())
            gateway.describe(destination, 443).use { assertEquals(token, metadata(it).getString("token")) }
            gateway.close()
            assertTrue(source.all { it == 'X'.code.toByte() })
        }
    }

    @Test fun `configuration validates token shape and readiness bounds`() {
        for (bytes in listOf(ByteArray(0), ByteArray(42), ByteArray(43) { '='.code.toByte() })) {
            assertThrows(IllegalArgumentException::class.java) { gateway(tokenBytes = bytes) }
        }
        for (millis in listOf(0, 30_001)) {
            assertThrows(IllegalArgumentException::class.java) { gateway(readyMillis = millis) }
        }
        for (port in listOf(0, 65536)) {
            assertThrows(IllegalArgumentException::class.java) { gateway(port) }
        }
    }

}
