// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.Tun2SocksBridge
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

/** No VPN route, host service, CA or capture file: inject an incomplete TCP
 * handshake into HEV's isolated packet socket and leave its SYN_RCVD PCB alive.
 * Reinitializing pools with that PCB still linked caused timer corruption.
 */
class Tun2SocksLwipLifecycleTest {
    @Test
    fun incompleteHandshakesReleasePoolStateAcrossTwentyRestarts() {
        assertFalse("Do not overlap an existing capture", LiveCaptureStore.state.value.isCapturing)
        assertFalse(Tun2SocksBridge.isRunning())
        val baseline = Tun2SocksBridge.getLwipCleanupStats()[0]
        repeat(20) { cycle ->
            val pair = requireNotNull(Tun2SocksBridge.createPacketSocketPair())
            val credentials = SocksCredentials.generate()
            ParcelFileDescriptor.adoptFd(pair[1]).use { peer ->
                // JNI consumes pair[0] even if startup fails. No ACK is sent, so
                // HEV never authenticates/dials this unused loopback SOCKS port.
                assertTrue(Tun2SocksBridge.start(pair[0],
                    LiveCaptureVpnService.buildTun2SocksConfig(9, credentials)))
                try {
                    val packet = syn(20000 + cycle)
                    assertEquals(packet.size, Os.write(peer.fileDescriptor, packet, 0, packet.size))
                    val response = ByteArray(2048)
                    val poll = StructPollfd().apply { fd = peer.fileDescriptor; events = OsConstants.POLLIN.toShort() }
                    assertTrue("isolated HEV must issue SYN-ACK", Os.poll(arrayOf(poll), 3000) > 0)
                    val length = Os.read(peer.fileDescriptor, response, 0, response.size)
                    assertTrue(length >= 40)
                    val tcp = (response[0].toInt() and 15) * 4
                    assertEquals(6, response[9].toInt() and 255)
                    assertEquals(0x12, response[tcp + 13].toInt() and 0x12)
                } finally {
                    val finished = CountDownLatch(1)
                    val failure = AtomicReference<Throwable>()
                    val start = SystemClock.elapsedRealtime()
                    Thread({
                        try { Tun2SocksBridge.stop() } catch (error: Throwable) { failure.set(error) }
                        finally { finished.countDown() }
                    }, "NIO-603-Isolated-Stop").start()
                    assertTrue("native stop must finish within 5s", finished.await(5, TimeUnit.SECONDS))
                    failure.get()?.let { throw it }
                    assertTrue(SystemClock.elapsedRealtime() - start <= 5000)
                    credentials.discard()
                }
            }
            assertFalse(Tun2SocksBridge.isRunning())
            val cleanup = Tun2SocksBridge.getLwipCleanupStats()
            assertEquals(baseline + cycle + 1, cleanup[0])
            assertTrue("the unacknowledged SYN must leave a PCB for cleanup", cleanup[1] >= 1)
            assertEquals("no TCP PCB may survive before memp_init", 0L, cleanup[2])
            assertEquals("no UDP PCB may survive allocator teardown", 0L, cleanup[3])
        }
    }

    private fun syn(port: Int): ByteArray {
        val packet = ByteArray(40)
        val bytes = ByteBuffer.wrap(packet)
        bytes.put(0, 0x45)
        bytes.putShort(2, 40)
        bytes.put(8, 64)
        bytes.put(9, 6)
        bytes.putInt(12, 0x0a6f0002)
        bytes.putInt(16, 0xc0000201.toInt()) // TEST-NET-1; stays inside the isolated virtual stack.
        bytes.putShort(20, port.toShort())
        bytes.putShort(22, 443)
        bytes.putInt(24, 1)
        bytes.put(32, 0x50)
        bytes.put(33, 2)
        bytes.putShort(34, 6553)
        bytes.putShort(10, checksum(packet.copyOfRange(0, 20)).toShort())
        val pseudo = packet.copyOfRange(12, 20) + byteArrayOf(0, 6, 0, 20) + packet.copyOfRange(20, 40)
        bytes.putShort(36, checksum(pseudo).toShort())
        return packet
    }

    private fun checksum(bytes: ByteArray): Int {
        var sum = 0
        for (index in bytes.indices step 2) {
            sum += ((bytes[index].toInt() and 255) shl 8) or (bytes.getOrElse(index + 1) { 0 }.toInt() and 255)
        }
        while (sum ushr 16 != 0) sum = (sum and 65535) + (sum ushr 16)
        return sum.inv() and 65535
    }
}
