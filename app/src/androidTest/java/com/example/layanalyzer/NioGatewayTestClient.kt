// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.os.SystemClock
import com.example.layanalyzer.capture.DirectSocks5Server
import com.example.layanalyzer.capture.tls.SocksNioTlsGateway
import java.io.DataInputStream
import java.io.IOException
import java.net.InetAddress
import java.net.Socket

/**
 * Drives engine-focused fixtures through the production NIO handshake and relay.
 * Each invocation owns its SOCKS listener; the caller still owns the shared Go gateway.
 * Capacity/load tests must own one shared DirectSocks5Server for the entire workload.
 */
internal fun <T> SocksNioTlsGateway.withNioConnection(
    address: String,
    port: Int,
    awaitRelayClose: Boolean = false,
    block: (Socket) -> T
): T {
    val borrowedGateway = object : SocksNioTlsGateway by this {
        override fun close() = Unit
    }
    return DirectSocks5Server(
        prepareTcp = { throw IOException("Expected the TLS gateway route") },
        prepareUdp = {}, resolveHost = InetAddress::getAllByName,
        tlsGateway = borrowedGateway
    ).use { socks ->
        val result = Socket(InetAddress.getByName("127.0.0.1"), socks.start()).use { client ->
            client.soTimeout = 15_000
            val input = DataInputStream(client.getInputStream())
            val output = client.getOutputStream()
            output.write(byteArrayOf(5, 1, 2))
            check(input.readUnsignedByte() == 5 && input.readUnsignedByte() == 2)
            val user = socks.credentials.username.toByteArray(Charsets.US_ASCII)
            val password = socks.credentials.password.toByteArray(Charsets.US_ASCII)
            output.write(byteArrayOf(1, user.size.toByte()) + user + byteArrayOf(password.size.toByte()) + password)
            check(input.readUnsignedByte() == 1 && input.readUnsignedByte() == 0)
            val destination = InetAddress.getByName(address).address
            output.write(byteArrayOf(5, 1, 0, if (destination.size == 4) 1 else 4) + destination +
                byteArrayOf((port ushr 8).toByte(), port.toByte()))
            check(input.readUnsignedByte() == 5)
            val reply = input.readUnsignedByte()
            check(input.readUnsignedByte() == 0)
            val size = when (input.readUnsignedByte()) {
                1 -> 4
                4 -> 16
                else -> throw IOException("Invalid SOCKS reply address")
            }
            input.readFully(ByteArray(size + 2))
            if (reply != 0) throw NioSocksRefusal(reply)
            block(client)
        }
        if (awaitRelayClose) {
            // A fully consumed response closes the client, but its FIN still has
            // to cross the NIO owners. Stopping the listener immediately can RST
            // the gateway peer and misclassify a successful bypass as failed.
            // Rejection/abrupt-stop fixtures keep the original immediate close.
            val deadline = SystemClock.elapsedRealtime() + 5_000
            while (socks.sessionStats().tcp.current != 0) {
                check(SystemClock.elapsedRealtime() < deadline) { "NIO relay did not finish before fixture stop" }
                SystemClock.sleep(10)
            }
        }
        result
    }
}

internal class NioSocksRefusal(val reply: Int) : IOException("NIO SOCKS refusal: $reply")
