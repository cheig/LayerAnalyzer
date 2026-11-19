// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Context
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.DirectSocks5Server
import com.example.layanalyzer.capture.SocksCredentials
import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicLongArray
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Same source is copied into the historical checkout for the baseline. It uses
 * that checkout's default facade, never restores a BLOCKING implementation here.
 * Device loopback, fixed eight drivers and one echo owner: not a WAN benchmark.
 */
@RunWith(AndroidJUnit4::class)
class NioForwardingPerformanceTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val args = InstrumentationRegistry.getArguments()
    private val loopback = InetAddress.getByName("127.0.0.1")

    @Test fun compare32Connections() = measure(32)
    @Test fun compare64Connections() = measure(64)

    private fun measure(count: Int) {
        val runId = args.getString("nio601RunId")
        assumeTrue("Opt-in historical forwarding comparison", runId != null)
        require(requireNotNull(runId).matches(Regex("[a-f0-9]{32}")))
        NativeTestSupport.awaitApplicationEngine()
        val out = File(context.getExternalFilesDir(null), "nio-601/$runId").apply { mkdirs() }
        val results = JSONArray()
        repeat(4) { round ->
            val sampler = ProcessResourceSampler(File(out, "performance-$count-$round.jsonl"), runId)
            val live = DirectSocks5Server(prepareTcp = { it.tcpNoDelay = true }, prepareUdp = {},
                resolveHost = { arrayOf(loopback) }, generateCredentials = { SocksCredentials.of("u", "p") })
            val clients = mutableListOf<Socket>()
            val workers = mutableListOf<Thread>()
            val running = AtomicBoolean(true)
            val failure = AtomicReference<Throwable>()
            val bytes = AtomicLong()
            // Log2 latency histogram, microseconds. Quantiles are bucket upper bounds,
            // with the same quantization for the baseline and candidate.
            val latency = AtomicLongArray(32)
            val echo = Echo()
            try {
                sampler.sample("before")
                val port = live.start()
                repeat(count) {
                    clients += Socket(loopback, port).apply {
                        soTimeout = 10000
                        tcpNoDelay = true
                        getOutputStream().write(byteArrayOf(5, 1, 2, 1, 1, 117, 1, 112,
                            5, 1, 0, 1, 127, 0, 0, 1, (echo.port ushr 8).toByte(), echo.port.toByte()))
                        val input = DataInputStream(getInputStream())
                        assertEquals(0x0502, input.readUnsignedShort())
                        assertEquals(0x0100, input.readUnsignedShort())
                        assertEquals(0x0500, input.readUnsignedShort())
                        input.readUnsignedByte()
                        val addressSize = when (input.readUnsignedByte()) { 1 -> 4; 4 -> 16; else -> error("SOCKS_ATYP") }
                        input.readFully(ByteArray(addressSize))
                        input.readUnsignedShort()
                    }
                }
                val started = SystemClock.elapsedRealtimeNanos()
                val duration = if (round == 0) 3 else 15
                val deadline = started + duration * 1_000_000_000L
                repeat(8) { index ->
                    workers += thread(name = "nio601-perf-$index", isDaemon = true) {
                        val payload = ByteArray(16384) { (it % 251).toByte() }
                        val reply = ByteArray(payload.size)
                        try {
                            while (running.get() && SystemClock.elapsedRealtimeNanos() < deadline) {
                                for (id in index until count step 8) {
                                    if (!running.get() || SystemClock.elapsedRealtimeNanos() >= deadline) break
                                    val peer = clients[id]
                                    val start = SystemClock.elapsedRealtimeNanos()
                                    peer.getOutputStream().write(payload)
                                    DataInputStream(peer.getInputStream()).readFully(reply)
                                    assertArrayEquals(payload, reply)
                                    val micros = maxOf(1L, (SystemClock.elapsedRealtimeNanos() - start) / 1000)
                                    val bucket = (64 - java.lang.Long.numberOfLeadingZeros(micros)).coerceAtMost(31)
                                    latency.incrementAndGet(bucket)
                                    bytes.addAndGet(payload.size * 2L)
                                }
                            }
                        } catch (error: Throwable) { failure.compareAndSet(null, error) }
                    }
                }
                SystemClock.sleep(1000)
                val held = sampler.sample("held")
                workers.forEach { it.join(30000) }
                assertTrue(workers.none { it.isAlive })
                failure.get()?.let { throw it }
                val elapsed = SystemClock.elapsedRealtimeNanos() - started
                val stopStart = SystemClock.elapsedRealtime()
                live.close()
                val stopMs = SystemClock.elapsedRealtime() - stopStart
                assertTrue("bounded stop", stopMs <= 5000)
                assertEquals(0, live.sessionStats().tcp.current)
                sampler.sample("after_stop")
                val total = (0 until latency.length()).sumOf { latency.get(it) }
                fun percentile(fraction: Double): Long {
                    var cumulative = 0L
                    for (bucket in 0 until latency.length()) {
                        cumulative += latency.get(bucket)
                        if (cumulative >= total * fraction) return 1L shl bucket
                    }
                    error("Missing latency samples")
                }
                results.put(JSONObject().put("warmup", round == 0).put("connections", count)
                    .put("mode", live.nioStats().mode).put("bytes", bytes.get()).put("elapsedNanos", elapsed)
                    .put("bytesPerSecond", bytes.get() * 1e9 / elapsed).put("p50UpperMicros", percentile(0.50))
                    .put("p95UpperMicros", percentile(0.95)).put("stopMs", stopMs)
                    .put("heldProcess", held.getJSONObject("process")))
            } finally {
                running.set(false)
                clients.forEach { runCatching { it.close() } }
                workers.forEach { it.join(10000) }
                live.close()
                echo.close()
                sampler.close()
            }
        }
        File(out, "performance-$count.json").writeText(JSONObject().put("status", "PASS")
            .put("runId", runId).put("tlsBuilt", BuildConfig.TLS_ENABLED).put("samples", results).toString(2))
    }

    private inner class Echo : AutoCloseable {
        private val selector = Selector.open()
        private val listener = ServerSocketChannel.open().apply {
            configureBlocking(false)
            bind(InetSocketAddress(loopback, 0), 128)
            register(selector, SelectionKey.OP_ACCEPT)
        }
        val port = (listener.localAddress as InetSocketAddress).port
        private val stopped = AtomicBoolean()
        private val failure = AtomicReference<Throwable>()
        private val worker = thread(name = "nio601-perf-echo", isDaemon = true) {
            try {
                while (!stopped.get()) {
                    selector.select(200)
                    val keys = selector.selectedKeys().iterator()
                    while (keys.hasNext()) {
                        val key = keys.next().also { keys.remove() }
                        if (!key.isValid) continue
                        if (key.isAcceptable) {
                            while (true) {
                                val channel = listener.accept() ?: break
                                channel.configureBlocking(false)
                                channel.socket().tcpNoDelay = true
                                channel.register(selector, SelectionKey.OP_READ, ByteBuffer.allocate(32768))
                            }
                        } else {
                            val channel = key.channel() as SocketChannel
                            val buffer = key.attachment() as ByteBuffer
                            try {
                                if (key.isReadable && channel.read(buffer) < 0) {
                                    key.cancel(); channel.close(); continue
                                }
                                buffer.flip()
                                while (buffer.hasRemaining()) if (channel.write(buffer) <= 0) break
                                buffer.compact()
                                key.interestOps(if (buffer.position() > 0) SelectionKey.OP_WRITE else SelectionKey.OP_READ)
                            } catch (_: java.io.IOException) { key.cancel(); channel.close() }
                        }
                    }
                }
            } catch (error: Throwable) { if (!stopped.get()) failure.set(error) }
            finally {
                runCatching { selector.keys().toList().forEach { it.channel().close() } }
                selector.close()
            }
        }
        override fun close() {
            stopped.set(true)
            selector.wakeup()
            worker.join(5000)
            assertFalse("echo worker must stop", worker.isAlive)
            failure.get()?.let { throw it }
        }
    }
}
