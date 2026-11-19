// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import com.example.layanalyzer.model.*
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class PacketDataSourceParsingTest {
    private val ref = PacketDataSnapshotRef("snapshot-1", 8, 3)
    private val raw = PacketDataSourceDescriptor("raw", "Frame", PacketDataSourceKind.RawFrame, 3, 3, false)

    private fun envelope() = JSONObject("""{
        "schemaVersion":1,"success":true,"errorCode":null,"error":null,
        "snapshotId":"snapshot-1","dissectionGeneration":8,"frameNumber":3
    }""")

    private fun description(id: String = "raw", kind: String = "raw_frame", size: Long = 3, available: Int = 3) =
        JSONObject().put("id", id).put("name", id).put("kind", kind).put("byteLength", size)
            .put("availableLength", available).put("truncated", available < size)

    private fun sources(vararg descriptions: JSONObject) =
        envelope().put("sources", JSONArray(descriptions.toList()))

    private fun chunk(encoded: String = "AAEC") = envelope().put("sourceId", "raw")
        .put("offset", 0).put("length", 3).put("byteLength", 3).put("availableLength", 3)
        .put("truncated", false).put("bytesBase64", encoded)

    private fun fails(code: String = "INVALID_RESPONSE", action: () -> Unit) {
        val error = assertThrows(PacketDataSourceException::class.java, action)
        assertEquals(code, error.errorCode)
        assertFalse(error.toString().contains("secret-marker"))
        assertNull(error.cause)
    }

    @Test fun nativeSourcesPreserveKindsAndTruncation() {
        val parsed = PacketDataSourceParser.sources(sources(
            description(), description("source-1", "reassembled", 8, 4),
            description("source-2", "decrypted_tls", 19, 0),
            description("source-3", "derived"), description("source-4", "future_kind")
        ).toString(), ref)
        assertEquals(listOf(PacketDataSourceKind.RawFrame, PacketDataSourceKind.Reassembled,
            PacketDataSourceKind.DecryptedTls, PacketDataSourceKind.Derived, PacketDataSourceKind.Unknown), parsed.map { it.kind })
        assertTrue(parsed[1].truncated)
        assertEquals(0, parsed[2].availableLength)
    }

    @Test fun detailMetadataIsOptionalOnlyAsAWholeForLegacy() {
        assertNull(PacketDataSourceParser.detailRef(JSONObject("""{"label":"IPv4"}"""), 3, 8))
        assertEquals(ref, PacketDataSourceParser.detailRef(envelope(), 3, 8))
        fails { PacketDataSourceParser.detailRef(JSONObject("""{"snapshotId":"snapshot-1"}"""), 3, 8) }
        fails { PacketDataSourceParser.detailRef(envelope(), 4, 8) }
        fails { PacketDataSourceParser.detailRef(envelope(), 3, 9) }
    }

    @Test fun legacyTreeAndRawIdentityAreConservative() {
        val repository = PacketRepository()
        val legacy = JSONObject("""{"label":"IPv4","start":0,"length":3,"children":[{"label":"value"}]}""")
        val node = repository.parseProtocolNode(legacy)
        assertEquals("IPv4", node.label)
        assertEquals(1, node.children.size)
        assertNull(node.dataSourceId)
        assertFalse(node.offsetValid)
        assertNull(node.byteRange("raw", 3))
        val confirmed = repository.parseProtocolNode(legacy.put("dataSourceId", "raw"))
        assertTrue(confirmed.offsetValid)
        assertEquals(0..2, confirmed.byteRange("raw", 3))
        assertFalse(repository.parseProtocolNode(legacy.put("dataSourceId", "source-1")).offsetValid)
    }

    @Test fun detailErrorsWithoutSnapshotsCannotMasqueradeAsLegacySuccess() {
        fails("STALE_GENERATION") {
            PacketDataSourceParser.detailRef(JSONObject("""{
                "schemaVersion":1,"success":false,"errorCode":"STALE_GENERATION","error":"secret-marker"
            }"""), 3, 8)
        }
        fails {
            PacketDataSourceParser.detailRef(envelope().apply { remove("snapshotId"); remove("dissectionGeneration") }, 3, 8)
        }
    }

    @Test fun nodeRequiresExactSourceValidOffsetAndRealField() {
        val repository = PacketRepository()
        val json = JSONObject("""{"label":"body","start":1,"length":2,"dataSourceId":"source-1","offsetValid":true}""")
        val node = repository.parseProtocolNode(json)
        assertEquals(1..2, node.byteRange("source-1", 3))
        assertNull(node.byteRange("raw", 3))
        assertNull(node.byteRange("source-1", 2))
        assertFalse(repository.parseProtocolNode(JSONObject(json.toString()).put("generated", true)).offsetValid)
        assertFalse(repository.parseProtocolNode(JSONObject(json.toString()).put("offsetValid", false)).offsetValid)
        assertFalse(repository.parseProtocolNode(JSONObject(json.toString()).put("dataSourceId", JSONObject.NULL)).offsetValid)
        assertFalse(repository.parseProtocolNode(JSONObject(json.toString()).apply { remove("start") }).offsetValid)
        assertFalse(repository.parseProtocolNode(JSONObject(json.toString()).put("start", -1)).offsetValid)
        assertFalse(repository.parseProtocolNode(JSONObject(json.toString()).put("length", Int.MAX_VALUE)).offsetValid)
        assertFalse(repository.parseProtocolNode(JSONObject(json.toString()).put("start", 4294967297L)).offsetValid)
        assertFalse(repository.parseProtocolNode(JSONObject(json.toString()).put("start", "1")).offsetValid)
    }

    @Test fun chunksPreserveBytesIncludingZeroAndSourceOffset() {
        val parsed = PacketDataSourceParser.chunk(chunk().toString(), ref, raw, 0, 3)
        assertArrayEquals(byteArrayOf(0, 1, 2), parsed.bytes)
        assertEquals(ref, parsed.snapshot)
        val tail = chunk("").put("offset", 3).put("length", 0)
        assertTrue(PacketDataSourceParser.chunk(tail.toString(), ref, raw, 3, 0).bytes.isEmpty())
    }

    @Test fun base64FailuresNeverBecomeEmptySuccess() {
        listOf("", "!!!!", "AAE", "AAEC\n", "secret-marker", "AA==").forEach { encoded ->
            fails { PacketDataSourceParser.chunk(chunk(encoded).toString(), ref, raw, 0, 3) }
        }
        val oneByte = raw.copy(byteLength = 1, availableLength = 1)
        val malformedPadding = chunk("AB==").put("length", 1).put("byteLength", 1).put("availableLength", 1)
        fails { PacketDataSourceParser.chunk(malformedPadding.toString(), ref, oneByte, 0, 1) }
    }

    @Test fun staleEnvelopeIsStructuredAndDoesNotExposeNativeText() {
        val json = """{"schemaVersion":1,"success":false,"errorCode":"STALE_GENERATION","error":"secret-marker"}"""
        fails("STALE_GENERATION") { PacketDataSourceParser.sources(json, ref) }
        fails("STALE_GENERATION") { PacketDataSourceParser.chunk(json, ref, raw, 0, 3) }
    }

    @Test fun responseCannotSubstituteCaptureFrameGenerationSourceOrRange() {
        mapOf("snapshotId" to "snapshot-2", "frameNumber" to 4, "dissectionGeneration" to 9,
            "sourceId" to "source-1", "offset" to 1, "length" to 2).forEach { (key, value) ->
            fails { PacketDataSourceParser.chunk(chunk().put(key, value).toString(), ref, raw, 0, 3) }
        }
        fails { PacketDataSourceParser.sources(sources(description()).put("frameNumber", 2).toString(), ref) }
    }

    @Test fun sourceListsRejectDuplicateIdsUnconfirmedRawAndInvalidLengths() {
        listOf(
            sources(description(), description()), sources(description("source-1", "decrypted_tls")),
            sources(description(kind = "derived")), sources(description(size = -1)),
            sources(description(size = 1, available = 2)),
            sources(description(available = -1)), sources(description().put("truncated", true)),
            sources(description().put("availableLength", 4294967299L)),
            sources(description().put("availableLength", "3")), sources(description().put("byteLength", 3.5)),
            sources(description().put("id", "../secret-marker"))
        ).forEach { fails { PacketDataSourceParser.sources(it.toString(), ref) } }
    }

    @Test fun snapshotAndRangeBudgetsAreEnforcedBeforeDecode() {
        fails { PacketDataSourceParser.sources(sources(
            description(size = PACKET_DATA_SNAPSHOT_LIMIT.toLong(), available = PACKET_DATA_SNAPSHOT_LIMIT),
            description("source-1", "decrypted_tls")
        ).toString(), ref) }
        val big = raw.copy(byteLength = Int.MAX_VALUE.toLong(), availableLength = PACKET_DATA_SNAPSHOT_LIMIT, truncated = true)
        listOf(-1 to 1, 0 to -1, Int.MAX_VALUE to Int.MAX_VALUE, 0 to PACKET_DATA_RANGE_LIMIT + 1,
            PACKET_DATA_SNAPSHOT_LIMIT to 1).forEach { (offset, length) ->
            fails("INVALID_ARGUMENT") { PacketDataSourceParser.chunk("secret-marker", ref, big, offset, length) }
        }
        PacketDataSourceParser.validateRange(big, PACKET_DATA_SNAPSHOT_LIMIT - PACKET_DATA_RANGE_LIMIT, PACKET_DATA_RANGE_LIMIT)
    }

    @Test fun missingOrMalformedEnvelopesFailClosed() {
        listOf("{}", "secret-marker", "[]", sources(description()).put("success", "true").toString(),
            sources(description()).put("schemaVersion", 2).toString()).forEach {
            fails { PacketDataSourceParser.sources(it, ref) }
        }
    }

    @Test fun userFrameConversionOccursOnceAndRejectsOverflow() {
        val repository = PacketRepository()
        assertEquals(0, repository.packetIndex(1))
        assertEquals(2, repository.packetIndex(3))
        assertEquals(Int.MAX_VALUE - 1, repository.packetIndex(Int.MAX_VALUE.toLong()))
        listOf(0L, -1L, Int.MAX_VALUE.toLong() + 1, Long.MAX_VALUE).forEach {
            assertThrows(IllegalArgumentException::class.java) { repository.packetIndex(it) }
        }
    }
}
