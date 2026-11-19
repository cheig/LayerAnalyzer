// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import java.io.IOException
import java.net.InetAddress
import java.nio.ByteBuffer
import org.junit.Assert.*
import org.junit.Test

class SocksIncrementalProtocolTest {
    private val credentials = SocksCredentials.of("User", "Password")
    private val auth = byteArrayOf(1, 4) + "User".toByteArray() + byteArrayOf(8) + "Password".toByteArray()
    private val destinations = listOf(
        SocksDestination.Ip(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))),
        SocksDestination.Ip(InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 })),
        SocksDestination.Domain("Do-Not-Resolve.example.invalid"),
        SocksDestination.Domain("x".repeat(255))
    )

    @Test fun greetingEveryIncompletePrefixConsumesNothing() {
        val frame = byteArrayOf(5, 3, 0, 1, 2)
        prefixes(frame) { SocksIncrementalProtocol.greeting(it) }
    }
    @Test fun authenticationEveryIncompletePrefixConsumesNothing() {
        prefixes(auth) { SocksIncrementalProtocol.authentication(it) { credentials } }
    }
    @Test fun allRequestTypesEveryIncompletePrefixConsumesNothing() {
        destinations.forEach { destination ->
            prefixes(SocksProtocol.encodeRequest(SocksRequest(1, destination, 65535))) { SocksIncrementalProtocol.request(it) }
        }
    }
    @Test fun completeCoalescedFramesLeaveExactApplicationSuffix() {
        destinations.forEach { destination ->
            val request = SocksRequest(3, destination, 53)
            val suffix = byteArrayOf(0x16, 3, 1, 0, 0xff.toByte())
            val input = ByteBuffer.wrap(byteArrayOf(5, 1, 2) + auth + SocksProtocol.encodeRequest(request) + suffix)
            assertEquals(2, SocksIncrementalProtocol.greeting(input)!!.method)
            assertTrue(SocksIncrementalProtocol.authentication(input) { credentials }!!.accepted)
            assertEquals(request, SocksIncrementalProtocol.request(input))
            assertArrayEquals(suffix, ByteArray(input.remaining()).also { input.get(it) })
        }
    }
    @Test fun maximumUsernamePasswordAndMethodsHaveBoundedUnsignedLengths() {
        val pair = SocksCredentials.of("u".repeat(255), "p".repeat(255))
        val frame = byteArrayOf(1, 0xff.toByte()) + pair.username.toByteArray() + byteArrayOf(0xff.toByte()) + pair.password.toByteArray()
        prefixes(frame) { SocksIncrementalProtocol.authentication(it) { pair } }
        val greeting = byteArrayOf(5, 0xff.toByte()) + ByteArray(255).also { it[254] = 2 }
        prefixes(greeting) { SocksIncrementalProtocol.greeting(it) }
    }
    @Test fun wrongGreetingVersionClosesWithoutWaitingForMethods() {
        val input = ByteBuffer.wrap(byteArrayOf(4, 1, 2))
        assertNull(SocksIncrementalProtocol.greeting(input)!!.method)
        assertEquals(1, input.position())
    }
    @Test fun zeroMethodsAndNoPasswordMethodReplyNoAcceptable() {
        listOf(byteArrayOf(5, 0), byteArrayOf(5, 2, 0, 1)).forEach {
            assertEquals(255, SocksIncrementalProtocol.greeting(ByteBuffer.wrap(it))!!.method)
        }
    }
    @Test fun emptyCredentialFieldsKeepOldFailureVerdict() {
        assertFalse(SocksIncrementalProtocol.authentication(ByteBuffer.wrap(byteArrayOf(1, 0, 0))) { credentials }!!.accepted)
    }
    @Test fun invalidAuthVersionStillConsumesWholeAuthBeforeFailure() {
        val frame = auth.clone().also { it[0] = 5 }
        prefixes(frame, complete = { assertFalse((it as SocksIncrementalProtocol.Authentication).accepted) }) {
            SocksIncrementalProtocol.authentication(it) { credentials }
        }
    }
    @Test fun nullDiscardedAndMismatchingCredentialsFail() {
        val discarded = SocksCredentials.of("User", "Password").also { it.discard() }
        listOf(null, discarded, SocksCredentials.of("Other", "Password")).forEach { pair ->
            assertFalse(SocksIncrementalProtocol.authentication(ByteBuffer.wrap(auth)) { pair }!!.accepted)
        }
    }
    @Test fun invalidRequestVersionAddressAndLengthKeepEarlyIoFailure() {
        listOf(byteArrayOf(4), byteArrayOf(5, 1, 0, 2), byteArrayOf(5, 1, 0, 3, 0)).forEach {
            assertThrows(IOException::class.java) { SocksIncrementalProtocol.request(ByteBuffer.wrap(it)) }
        }
    }
    @Test fun reservedByteToleranceAndUnknownCommandRemainCodecBehavior() {
        val request = SocksRequest(127, destinations[0], 0)
        val frame = SocksProtocol.encodeRequest(request).also { it[2] = 99 }
        assertEquals(request, SocksIncrementalProtocol.request(ByteBuffer.wrap(frame)))
    }
    @Test fun readOnlyAndNonzeroPositionInputAreSupported() {
        val request = SocksRequest(1, destinations[2], 443)
        val frame = SocksProtocol.encodeRequest(request)
        val input = ByteBuffer.wrap(byteArrayOf(99, 99) + frame + byteArrayOf(42)).asReadOnlyBuffer()
        input.position(2)
        assertEquals(request, SocksIncrementalProtocol.request(input))
        assertEquals(42.toByte(), input.get())
    }
    @Test fun credentialsCallbackExceptionIsPropagatedAfterExactAuthConsumption() {
        val input = ByteBuffer.wrap(auth + byteArrayOf(42))
        assertThrows(IllegalStateException::class.java) {
            SocksIncrementalProtocol.authentication(input) { throw IllegalStateException("fixture") }
        }
        assertEquals(auth.size, input.position())
        assertEquals(42.toByte(), input.get())
    }

    private fun prefixes(frame: ByteArray, complete: (Any) -> Unit = {}, parse: (ByteBuffer) -> Any?) {
        for (size in 0 until frame.size) {
            val input = ByteBuffer.wrap(frame.copyOf(size))
            assertNull("size=$size", parse(input))
            assertEquals("size=$size", 0, input.position())
        }
        val input = ByteBuffer.wrap(frame)
        complete(checkNotNull(parse(input)))
        assertEquals(frame.size, input.position())
    }
}
