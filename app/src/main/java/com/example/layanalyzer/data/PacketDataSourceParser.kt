// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import com.example.layanalyzer.model.*
import org.json.JSONObject
import java.util.Base64

/** Fail closed on malformed metadata/base64, and never include native payloads in exceptions. */
internal object PacketDataSourceParser {
    private val idPattern = Regex("[a-z0-9-]{1,96}")

    fun detailRef(json: JSONObject, frameNumber: Long, generation: Long): PacketDataSnapshotRef? = checked {
        if (!json.has("snapshotId") && !json.has("dissectionGeneration")) {
            if (json.has("schemaVersion") || json.has("success")) {
                envelope(json) // A native failure is never a successful legacy tree.
                throw IllegalArgumentException()
            }
            return@checked null
        }
        envelope(json)
        reference(json).also {
            require(it.frameNumber == frameNumber && it.dissectionGeneration == generation)
        }
    }

    fun sources(raw: String, expected: PacketDataSnapshotRef): List<PacketDataSourceDescriptor> = checked {
        val json = JSONObject(raw)
        envelope(json)
        require(reference(json) == expected)
        val array = json.getJSONArray("sources")
        require(array.length() in 1..4096)
        val sources = List(array.length()) { index ->
            val item = array.getJSONObject(index)
            val id = id(item, "id")
            val kind = PacketDataSourceKind.fromWire(item.getString("kind"))
            require((id == "raw") == (kind == PacketDataSourceKind.RawFrame))
            val (size, available, truncated) = lengths(item)
            PacketDataSourceDescriptor(id, item.getString("name"), kind, size, available, truncated)
        }
        require(sources.map { it.id }.distinct().size == sources.size)
        require(sources.count { it.id == "raw" } == 1)
        require(sources.sumOf { it.availableLength.toLong() } <= PACKET_DATA_SNAPSHOT_LIMIT)
        sources
    }

    fun chunk(
        raw: String, expected: PacketDataSnapshotRef, source: PacketDataSourceDescriptor,
        offset: Int, length: Int
    ): PacketDataSourceChunk = checked {
        validateRange(source, offset, length)
        val json = JSONObject(raw)
        envelope(json)
        require(reference(json) == expected && id(json, "sourceId") == source.id)
        require(integer(json, "offset") == offset.toLong() && integer(json, "length") == length.toLong())
        val (size, available, truncated) = lengths(json)
        require(size == source.byteLength && available == source.availableLength && truncated == source.truncated)
        val encoded = json.getString("bytesBase64")
        // Native emits canonical padded base64. Check length before allocating the decoded buffer.
        require(encoded.length == ((length + 2) / 3) * 4)
        val bytes = Base64.getDecoder().decode(encoded)
        require(bytes.size == length && Base64.getEncoder().encodeToString(bytes) == encoded)
        PacketDataSourceChunk(expected, source.id, offset, bytes, size, available, truncated)
    }

    fun validateRange(source: PacketDataSourceDescriptor, offset: Int, length: Int) {
        if (offset < 0 || length !in 0..PACKET_DATA_RANGE_LIMIT || offset > source.availableLength ||
            length > source.availableLength - offset
        ) throw PacketDataSourceException("INVALID_ARGUMENT")
    }

    private fun lengths(json: JSONObject): Triple<Long, Int, Boolean> {
        val size = integer(json, "byteLength")
        val available = integer(json, "availableLength")
        val truncated = json.get("truncated") as Boolean
        require(size >= 0 && available in 0..PACKET_DATA_SNAPSHOT_LIMIT.toLong() && available <= size)
        require(truncated == (available < size))
        return Triple(size, available.toInt(), truncated)
    }

    private fun reference(json: JSONObject) = PacketDataSnapshotRef(
        id(json, "snapshotId"), integer(json, "dissectionGeneration").also { require(it >= 0) },
        integer(json, "frameNumber").also { require(it in 1..Int.MAX_VALUE.toLong()) }
    )

    private fun id(json: JSONObject, key: String) = json.getString(key).also { require(idPattern.matches(it)) }

    private fun integer(json: JSONObject, key: String): Long {
        val value = json.get(key)
        require(value is Int || value is Long)
        return (value as Number).toLong()
    }

    private fun envelope(json: JSONObject) {
        require(integer(json, "schemaVersion") == 1L)
        if (!(json.get("success") as Boolean)) {
            val code = json.optString("errorCode")
            throw PacketDataSourceException(code.takeIf { it.matches(Regex("[A-Z_]{1,64}")) } ?: "UNKNOWN")
        }
        require(json.has("errorCode") && json.isNull("errorCode") && json.has("error") && json.isNull("error"))
    }

    private inline fun <T> checked(block: () -> T): T = try { block() }
    catch (e: PacketDataSourceException) { throw e }
    catch (_: Exception) { throw PacketDataSourceException("INVALID_RESPONSE") }
}
