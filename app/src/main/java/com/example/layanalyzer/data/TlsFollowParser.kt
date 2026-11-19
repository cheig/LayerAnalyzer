// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import com.example.layanalyzer.model.*
import org.json.JSONObject
import java.util.Base64

internal object TlsFollowParser {
    // 1 MiB Base64 plus at most 8192 small record envelopes; reject before JSON allocation.
    private const val MAX_RESPONSE_CHARS = 4 * 1024 * 1024

    fun parse(raw: String, expectedGeneration: Long, maxBytes: Int): TlsFollowResult {
        validateRequest(expectedGeneration, maxBytes)
        return try {
            require(raw.length <= MAX_RESPONSE_CHARS)
            val json = JSONObject(raw)
            require(integer(json, "schemaVersion") == 1L && json.getString("protocol") == "tls")
            require(json.getString("scope") == TlsFollowScope.CompleteConnection.wireName)
            val generation = integer(json, "dissectionGeneration")
            if (generation != expectedGeneration) throw TlsFollowException("STALE_GENERATION")
            val success = json.get("success") as Boolean
            val known = json.get("directionKnown") as Boolean
            val truncated = json.get("truncated") as Boolean
            val incomplete = json.get("incomplete") as Boolean
            val array = json.getJSONArray("records")
            require(array.length() <= TLS_FOLLOW_RECORD_LIMIT)
            val stream = optionalInteger(json, "streamId", 0..Int.MAX_VALUE)
            val frames = optionalInteger(json, "connectionFrames", 1..Int.MAX_VALUE)
            require(json.has("unavailableReason") && json.has("errorCode") && json.has("error"))
            val reason = if (json.isNull("unavailableReason")) null else
                TlsFollowUnavailableReason.fromWire(json.getString("unavailableReason"))

            if (!success) {
                // Never decode or expose records from a failed/cancelled scan.
                require(array.length() == 0 && incomplete && !json.isNull("errorCode"))
                require(!json.has("byteLength") || integer(json, "byteLength") == 0L)
                val error = TlsErrorCode.fromWire(json.getString("errorCode"))
                require(reason == null || error == TlsErrorCode.NOT_READY)
                return TlsFollowResult(false, TlsFollowScope.CompleteConnection, generation, known,
                    emptyList(), truncated, incomplete, stream, frames, error, reason)
            }

            require(json.isNull("errorCode") && json.isNull("error") && reason == null)
            require(stream != null && frames != null && array.length() > 0)
            require((!truncated && known) || incomplete)
            val size = integer(json, "byteLength")
            require(size in 1..maxBytes.toLong())
            var used = 0
            val records = List(array.length()) { index ->
                val item = array.getJSONObject(index)
                val frame = integer(item, "frameNumber")
                require(frame in 1..Int.MAX_VALUE.toLong())
                val direction = TlsFollowDirection.entries.firstOrNull { it.wireName == item.getString("direction") }
                    ?: throw IllegalArgumentException()
                require(item.has("fromServer"))
                val server = if (item.isNull("fromServer")) null else item.get("fromServer") as Boolean
                if (known) require(direction != TlsFollowDirection.Unknown &&
                    server == (direction == TlsFollowDirection.Server))
                else require(direction == TlsFollowDirection.Unknown && server == null)
                val length = integer(item, "byteLength")
                require(length in 1..(maxBytes - used).toLong())
                val encoded = item.getString("bytesBase64")
                require(encoded.length.toLong() == ((length + 2) / 3) * 4)
                val bytes = Base64.getDecoder().decode(encoded)
                require(bytes.size.toLong() == length && Base64.getEncoder().encodeToString(bytes) == encoded)
                used += bytes.size
                TlsFollowRecord(frame, direction, server, bytes)
            }
            require(used.toLong() == size)
            TlsFollowResult(true, TlsFollowScope.CompleteConnection, generation, known, records,
                truncated, incomplete, stream, frames, null, null)
        } catch (e: TlsFollowException) {
            throw e
        } catch (_: Exception) {
            throw TlsFollowException("INVALID_RESPONSE")
        }
    }

    fun validateRequest(generation: Long, maxBytes: Int) {
        if (generation < 0 || maxBytes !in 1..TLS_FOLLOW_PREVIEW_LIMIT) throw TlsFollowException("INVALID_ARGUMENT")
    }

    /**
     * TLS-308 export envelope. No bytes are ever returned here: the plaintext went straight to the
     * file, and this only carries its length, SHA-256 and the honest truncation/incomplete flags.
     * A failed or cancelled export must have no digest and a zero length, so a half file can never be
     * surfaced as a completed export.
     */
    fun parseExport(raw: String, expectedGeneration: Long, maxBytes: Int): TlsFollowExportResult {
        if (expectedGeneration < 0 || maxBytes !in 1..TLS_FOLLOW_EXPORT_LIMIT) {
            throw TlsFollowException("INVALID_ARGUMENT")
        }
        return try {
            require(raw.length <= MAX_RESPONSE_CHARS)
            val json = JSONObject(raw)
            require(integer(json, "schemaVersion") == 1L && json.getString("protocol") == "tls")
            require(json.getString("scope") == TlsFollowScope.CompleteConnection.wireName)
            val generation = integer(json, "dissectionGeneration")
            if (generation != expectedGeneration) throw TlsFollowException("STALE_GENERATION")
            val success = json.get("success") as Boolean
            val known = json.get("directionKnown") as Boolean
            val truncated = json.get("truncated") as Boolean
            val incomplete = json.get("incomplete") as Boolean
            val stream = optionalInteger(json, "streamId", 0..Int.MAX_VALUE)
            val frames = optionalInteger(json, "connectionFrames", 1..Int.MAX_VALUE)
            require(json.has("unavailableReason") && json.has("errorCode") && json.has("error") &&
                json.has("sha256") && json.has("byteLength"))
            val reason = if (json.isNull("unavailableReason")) null else
                TlsFollowUnavailableReason.fromWire(json.getString("unavailableReason"))

            if (!success) {
                require(json.isNull("sha256"))
                require(integer(json, "byteLength") == 0L)
                require(incomplete && !json.isNull("errorCode"))
                val error = TlsErrorCode.fromWire(json.getString("errorCode"))
                require(reason == null || error == TlsErrorCode.NOT_READY)
                return TlsFollowExportResult(false, 0L, null, truncated, incomplete, known,
                    stream, frames, error, reason)
            }

            require(json.isNull("errorCode") && json.isNull("error") && reason == null)
            require(stream != null && frames != null)
            require((!truncated && known) || incomplete)
            val size = integer(json, "byteLength")
            require(size in 1..maxBytes.toLong())
            val digest = json.getString("sha256")
            require(digest.length == 64 && digest.all { it in '0'..'9' || it in 'a'..'f' })
            TlsFollowExportResult(true, size, digest, truncated, incomplete, known, stream, frames, null, null)
        } catch (e: TlsFollowException) {
            throw e
        } catch (_: Exception) {
            throw TlsFollowException("INVALID_RESPONSE")
        }
    }

    private fun integer(json: JSONObject, key: String): Long {
        val value = json.get(key)
        require(value is Int || value is Long)
        return (value as Number).toLong()
    }

    private fun optionalInteger(json: JSONObject, key: String, range: IntRange): Int? =
        if (!json.has(key)) null else integer(json, key).also {
            require(it in range.first.toLong()..range.last.toLong())
        }.toInt()
}
