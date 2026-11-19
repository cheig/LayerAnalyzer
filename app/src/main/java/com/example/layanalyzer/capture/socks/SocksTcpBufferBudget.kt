// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Shared across all loops in one server. Reserve both directions before starting connect so an
 * admitted relay can always allocate its bounded buffers; there is no pool or memory wait queue.
 * Reservation is accounting only: idle sessions allocate no data storage. Existing reservations
 * cannot be displaced by newer sessions. Production capacity is unchanged by this internal type.
 */
internal class SocksTcpBufferBudget(
    val capacityBytes: Int = 64 * 2 * MAX_DIRECTION_BYTES,
    val directionBytes: Int = MAX_DIRECTION_BYTES
) {
    init {
        require(directionBytes in SocksNioHandshake.INPUT_BYTES..MAX_DIRECTION_BYTES)
        require(capacityBytes >= 2 * directionBytes)
    }

    data class Snapshot(val reservedBytes: Int, val allocatedBytes: Int, val peakAllocatedBytes: Int,
        val rejectedReservations: Long, val allocationFailures: Long)

    private val reserved = AtomicInteger()
    private val allocated = AtomicInteger()
    private val peak = AtomicInteger()
    private val rejected = AtomicLong()
    private val allocationFailures = AtomicLong()

    fun snapshot() = Snapshot(reserved.get(), allocated.get(), peak.get(), rejected.get(), allocationFailures.get())

    internal fun reserve(owner: SocksEventLoop): Reservation? {
        check(owner.inEventLoop())
        val bytes = 2 * directionBytes
        while (true) {
            val current = reserved.get()
            if (bytes > capacityBytes - current) { rejected.incrementAndGet(); return null }
            if (reserved.compareAndSet(current, current + bytes)) return Reservation(owner)
        }
    }

    inner class Reservation internal constructor(private val owner: SocksEventLoop) {
        val budget: SocksTcpBufferBudget get() = this@SocksTcpBufferBudget
        private val buffers = arrayOfNulls<ByteBuffer>(2)
        private var closed = false
        val bufferCount: Int get() = buffers.count { it != null }
        val bufferBytes: Int get() = bufferCount * directionBytes

        fun existing(direction: Int): ByteBuffer? { check(owner.inEventLoop()); return buffers[direction] }

        fun buffer(direction: Int): ByteBuffer {
            check(owner.inEventLoop() && !closed)
            return buffers[direction] ?: try {
                ByteBuffer.allocate(directionBytes).also {
                    buffers[direction] = it
                    val current = allocated.addAndGet(directionBytes)
                    peak.updateAndGet { previous -> maxOf(previous, current) }
                }
            } catch (error: OutOfMemoryError) {
                allocationFailures.incrementAndGet()
                throw error // owner scope closes explicitly, returning the reservation
            }
        }

        fun close() {
            check(owner.inEventLoop())
            if (closed) return
            closed = true
            buffers.indices.forEach { index ->
                buffers[index]?.let { buffer ->
                    buffer.clear()
                    while (buffer.hasRemaining()) buffer.put(0)
                    buffers[index] = null
                    allocated.addAndGet(-directionBytes)
                }
            }
            reserved.addAndGet(-2 * directionBytes)
        }
    }

    companion object { const val MAX_DIRECTION_BYTES = 16 * 1024 }
}
