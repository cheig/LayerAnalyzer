// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * The RFC 1929 pair HEV must present to the loopback SOCKS5 hop.
 *
 * The alphabet is deliberately alphanumeric: the same bytes are handed to HEV
 * through its YAML configuration, so no character that YAML would have to quote,
 * escape or reinterpret may ever occur. Generation is independent from the TLS
 * gateway token (C05) — the two secrets are never derived from one another, so a
 * leaked pair cannot authenticate the gateway, and vice versa.
 */
internal class SocksCredentials private constructor(
    val username: String,
    val password: String
) {
    private val usernameBytes = username.toByteArray(StandardCharsets.US_ASCII)
    private val passwordBytes = password.toByteArray(StandardCharsets.US_ASCII)

    @Volatile
    private var discarded = false

    /**
     * Compares a peer-supplied pair without short-circuiting on the first
     * mismatch. A discarded pair never matches anything.
     */
    fun matches(candidateUsername: ByteArray, candidatePassword: ByteArray): Boolean =
        !discarded and
            MessageDigest.isEqual(usernameBytes, candidateUsername) and
            MessageDigest.isEqual(passwordBytes, candidatePassword)

    /** Invalidates the pair; a stopped session's credential can no longer be used. */
    fun discard() {
        discarded = true
        usernameBytes.fill(0)
        passwordBytes.fill(0)
    }

    /** The pair must never reach a log, a capture manifest or a crash report. */
    override fun toString(): String = "SocksCredentials(username=<redacted>, password=<redacted>)"

    companion object {
        const val USERNAME_LENGTH = 16
        const val PASSWORD_LENGTH = 32

        // RFC 1929 carries both fields in a single length octet; HEV copies at most
        // 255 bytes into its own request. Staying under that bound keeps the two
        // ends of the same configuration value byte-identical.
        private const val MAX_FIELD_LENGTH = 255

        private const val ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

        fun generate(random: SecureRandom = SecureRandom()): SocksCredentials = SocksCredentials(
            username = randomToken(random, USERNAME_LENGTH),
            password = randomToken(random, PASSWORD_LENGTH)
        )

        /** Builds a pair from caller-supplied values; used by tests and fixtures. */
        fun of(username: String, password: String): SocksCredentials {
            requireField(username, "username")
            requireField(password, "password")
            return SocksCredentials(username, password)
        }

        private fun requireField(value: String, name: String) {
            require(value.isNotEmpty()) { "SOCKS5 $name must not be empty." }
            require(value.length <= MAX_FIELD_LENGTH) { "SOCKS5 $name exceeds one length octet." }
            require(value.all { it in ALPHABET }) {
                "SOCKS5 $name must be alphanumeric so it can be written to YAML unquoted."
            }
        }

        private fun randomToken(random: SecureRandom, length: Int): String = buildString(length) {
            repeat(length) { append(ALPHABET[random.nextInt(ALPHABET.length)]) }
        }
    }
}
