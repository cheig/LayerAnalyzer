// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import java.io.File
import java.security.MessageDigest

/**
 * Calculates the stable identity used by workspaces and Agent sessions.
 *
 * The implementation intentionally lives outside [AnalysisWorkspaceStore] so
 * every consumer uses exactly the same byte-for-byte SHA-256 algorithm.  A
 * fingerprint is never represented by an empty string: callers should treat
 * an exception (or a blank result from a faulty implementation) as a failed
 * preparation step.
 */
open class CaptureFingerprintCalculator(
    private val algorithm: String = SHA_256
) {
    open fun calculate(file: File): String {
        require(file.isFile && file.canRead()) { "Capture file is not readable." }

        val digest = MessageDigest.getInstance(algorithm)
        file.inputStream().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read == 0) continue
                digest.update(buffer, 0, read)
            }
        }

        val bytes = digest.digest()
        return buildString(bytes.size * 2) {
            bytes.forEach { byte ->
                append(HEX[(byte.toInt() ushr 4) and 0x0f])
                append(HEX[byte.toInt() and 0x0f])
            }
        }
    }

    /** Compatibility alias for callers that use the workspace vocabulary. */
    fun fingerprint(file: File): String = calculate(file)

    fun calculateResult(file: File): Result<String> = runCatching {
        calculate(file).also { value ->
            require(value.isNotBlank()) { "Capture fingerprint is empty." }
        }
    }

    private companion object {
        const val SHA_256 = "SHA-256"
        const val HEX = "0123456789abcdef"
    }
}
