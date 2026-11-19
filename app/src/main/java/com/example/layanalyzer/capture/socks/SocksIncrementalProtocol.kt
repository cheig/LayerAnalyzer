// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksRequest
import java.nio.ByteBuffer

/** Read-mode input. Incomplete frames consume nothing; complete frames consume exactly themselves. */
internal object SocksIncrementalProtocol {
    data class Greeting(val method: Int?)
    data class Authentication(val accepted: Boolean)

    fun greeting(input: ByteBuffer): Greeting? {
        if (!input.hasRemaining()) return null
        if (unsigned(input, 0) != SocksProtocol.SOCKS_VERSION) {
            input.get()
            return Greeting(null) // Historical silent close, even without NMETHODS.
        }
        if (input.remaining() < 2) return null
        val count = unsigned(input, 1)
        if (input.remaining() < 2 + count) return null
        val version = input.get().toInt() and 0xff
        input.get()
        val methods = ByteArray(count).also { input.get(it) }
        return Greeting(SocksProtocol.selectAuthenticationMethod(version, methods))
    }

    fun authentication(input: ByteBuffer, credentials: () -> SocksCredentials?): Authentication? {
        if (input.remaining() < 2) return null
        val usernameLength = unsigned(input, 1)
        if (input.remaining() < 3 + usernameLength) return null
        val passwordLength = unsigned(input, 2 + usernameLength)
        if (input.remaining() < 3 + usernameLength + passwordLength) return null
        val version = input.get().toInt() and 0xff
        input.get()
        val username = ByteArray(usernameLength).also { input.get(it) }
        try {
            input.get()
            val password = ByteArray(passwordLength).also { input.get(it) }
            try {
                return Authentication(SocksProtocol.authenticationAccepted(version, username, password, credentials()))
            } finally {
                password.fill(0)
            }
        } finally {
            username.fill(0)
        }
    }

    fun request(input: ByteBuffer): SocksRequest? {
        if (!input.hasRemaining()) return null
        SocksProtocol.requireVersion(unsigned(input, 0))
        if (input.remaining() < 4) return null
        val type = unsigned(input, 3)
        val size = if (type == SocksProtocol.ADDRESS_TYPE_DOMAIN) {
            if (input.remaining() < 5) return null
            val length = unsigned(input, 4)
            SocksProtocol.requireDomainLength(length)
            7 + length
        } else {
            6 + SocksProtocol.ipAddressLength(type)
        }
        if (input.remaining() < size) return null
        val frame = ByteArray(size).also { input.get(it) }
        return SocksProtocol.decodeRequest(frame).also { check(it.bytesConsumed == size) }.request
    }

    private fun unsigned(input: ByteBuffer, offset: Int): Int = input.get(input.position() + offset).toInt() and 0xff
}
