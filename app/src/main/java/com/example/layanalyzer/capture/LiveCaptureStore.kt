// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import com.example.layanalyzer.capture.tls.TlsAssetException
import com.example.layanalyzer.capture.tls.TlsSecretAssetRef
import com.example.layanalyzer.data.CaptureArtifactRepository
import com.example.layanalyzer.data.CaptureFileAccess
import com.example.layanalyzer.model.CaptureArtifactManifest
import com.example.layanalyzer.model.CaptureSegmentRef
import com.example.layanalyzer.model.LiveCaptureManifestConfig
import com.example.layanalyzer.model.LiveCapturePacketPreview
import com.example.layanalyzer.model.LiveCaptureState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.ArrayDeque

object LiveCaptureStore {
    private const val RECENT_PACKET_LIMIT = 80
    private const val UI_UPDATE_INTERVAL_MILLIS = 250L

    private val _state = MutableStateFlow(LiveCaptureState())
    val state: StateFlow<LiveCaptureState> = _state.asStateFlow()

    private val lock = Any()
    private val recentPackets = ArrayDeque<LiveCapturePacketPreview>(RECENT_PACKET_LIMIT)
    private var capturing = false
    private var startedAtMillis = 0L
    private var stoppedAtMillis = 0L
    private var packetCount = 0L
    private var byteCount = 0L
    private var offeredPacketCount = 0L
    private var droppedPacketCount = 0L
    private var ioErrorCount = 0L
    private var lastIoError: String? = null
    private var outputPath: String? = null
    private val segmentRecords = mutableListOf<SegmentRecord>()
    private var captureId: String? = null
    private var manifestConfig: LiveCaptureManifestConfig? = null
    private var artifactRepository: CaptureArtifactRepository? = null
    private var writersDrained = false
    private var captureUse: AutoCloseable? = null
    private var secretsPersistedSequence = 0L
    private var interrupted = false
    private var incomplete = false
    private var preferences: android.content.SharedPreferences? = null
    private var lastPersistedAtMillis = 0L
    private var error: String? = null
    private var lastPublishedAtMillis = 0L

    fun initialize(context: Context) {
        synchronized(lock) {
            if (preferences != null) return
            val applicationContext = context.applicationContext
            preferences = applicationContext.getSharedPreferences("live_capture_state", Context.MODE_PRIVATE)
            artifactRepository = CaptureArtifactRepository(applicationContext)
            val raw = preferences?.getString("state", null) ?: return
            runCatching {
                val json = JSONObject(raw)
                capturing = false
                interrupted = json.optBoolean("capturing", false) || json.optBoolean("interrupted", false)
                incomplete = json.optBoolean("incomplete", false) || interrupted
                startedAtMillis = json.optLong("startedAtMillis")
                stoppedAtMillis = json.optLong("stoppedAtMillis")
                packetCount = json.optLong("packetCount")
                byteCount = json.optLong("byteCount")
                offeredPacketCount = json.optLong("offeredPacketCount")
                droppedPacketCount = json.optLong("droppedPacketCount")
                ioErrorCount = json.optLong("ioErrorCount")
                lastIoError = json.optNullableString("lastIoError")
                outputPath = json.optNullableString("outputPath")
                captureId = json.optNullableString("captureId")
                segmentRecords.clear()
                json.optJSONArray("segmentPaths")?.let { array ->
                    for (i in 0 until array.length()) {
                        array.optString(i).takeIf(String::isNotBlank)?.let { segmentRecords.add(SegmentRecord(it, 0L)) }
                    }
                }
                error = if (interrupted) "Capture process was interrupted; evidence is incomplete." else json.optNullableString("error")
                if (interrupted) writeInterruptedReport()
                publishLocked(force = true)
                persistLocked(force = true)
            }
        }
    }

    fun start(outputPath: String, manifest: LiveCaptureManifestConfig? = null) {
        synchronized(lock) {
            captureUse?.close()
            captureUse = CaptureFileAccess.retain(manifest?.let {
                artifactRepository?.captureDirectory(it.captureId)
            } ?: File(outputPath))
            capturing = true
            startedAtMillis = System.currentTimeMillis()
            stoppedAtMillis = 0L
            packetCount = 0L
            byteCount = 0L
            offeredPacketCount = 0L
            droppedPacketCount = 0L
            ioErrorCount = 0L
            lastIoError = null
            this.outputPath = outputPath
            manifestConfig = manifest
            captureId = manifest?.captureId
            writersDrained = false
            secretsPersistedSequence = 0L
            segmentRecords.clear()
            segmentRecords += SegmentRecord(outputPath, 0L)
            interrupted = false
            incomplete = false
            error = null
            recentPackets.clear()
            publishLocked(force = true)
            writeUnfinalizedArtifactsLocked()
        }
    }

    fun recordPacket(timestampMillis: Long, bytes: ByteArray, length: Int) {
        synchronized(lock) {
            if (!capturing) return
            val safeLength = length.coerceIn(0, bytes.size)
            packetCount += 1L
            byteCount += safeLength.toLong()
            recentPackets.addFirst(parsePreview(packetCount, timestampMillis, bytes, safeLength))
            while (recentPackets.size > RECENT_PACKET_LIMIT) {
                recentPackets.removeLast()
            }
            publishLocked(force = packetCount == 1L)
        }
    }

    fun recordSegment(path: String) {
        synchronized(lock) {
            // The frame count at the moment a new segment opens is exactly the frames
            // already persisted into the previous segments (the writer rotates before
            // the first packet of the new file), which is this segment's global origin.
            if (segmentRecords.none { it.path == path }) segmentRecords += SegmentRecord(path, packetCount)
            writeUnfinalizedArtifactsLocked()
            publishLocked(force = true)
        }
    }

    /** Confirms the PCAP writer drained cleanly; without it a capture is never complete. */
    fun recordWritersDrained() {
        synchronized(lock) {
            writersDrained = true
        }
    }

    /** Persisted secrets watermark reported to the manifest; not an accepted count. */
    fun recordSecretsPersistedSequence(sequence: Long) {
        synchronized(lock) {
            secretsPersistedSequence = sequence.coerceAtLeast(0L)
        }
    }

    /**
     * Records the published secrets asset and its watermark together (TLS-315 step 2),
     * so the manifest resolves the same persisted records for analysis and export (C08).
     *
     * Only an asset whose watermark is already on disk may be named: a run whose sink
     * never finished passes null, which leaves `secretsAssetId` absent rather than
     * pointing at a directory the analysis lease would refuse. It is recorded before
     * [stop]/[fail], which are the only calls that commit the manifest; calling it
     * without a manifest configuration (a TLS-disabled run) changes nothing.
     */
    fun recordSecretsAsset(asset: TlsSecretAssetRef?, complete: Boolean) {
        synchronized(lock) {
            val config = manifestConfig ?: return
            require(asset == null || asset.captureId == config.captureId)
            secretsPersistedSequence = asset?.watermark?.sequence ?: 0L
            manifestConfig = config.copy(
                tls = config.tls.copy(
                    secretsAssetId = asset?.assetId,
                    complete = complete && asset != null
                )
            )
        }
    }

    fun recordOffered() {
        synchronized(lock) {
            if (!capturing) return
            offeredPacketCount += 1L
            publishLocked(force = false)
        }
    }

    fun recordDropped(count: Long = 1L) {
        synchronized(lock) {
            if (count <= 0L) return
            droppedPacketCount += count
            publishLocked(force = false)
        }
    }

    fun recordIoError(message: String) {
        synchronized(lock) {
            ioErrorCount += 1L
            lastIoError = message
            publishLocked(force = true)
        }
    }

    fun stop() {
        synchronized(lock) {
            if (!capturing) return
            capturing = false
            stoppedAtMillis = System.currentTimeMillis()
            incomplete = incomplete || interrupted || droppedPacketCount > 0 || ioErrorCount > 0
            publishLocked(force = true)
            commitArtifactsLocked()
            manifestConfig = null
            captureUse?.close()
            captureUse = null
        }
    }

    fun fail(message: String) {
        synchronized(lock) {
            error = message
            if (!capturing) {
                publishLocked(force = true)
                return
            }
            capturing = false
            stoppedAtMillis = System.currentTimeMillis()
            incomplete = true
            publishLocked(force = true)
            commitArtifactsLocked()
            manifestConfig = null
            captureUse?.close()
            captureUse = null
        }
    }

    fun clearError() {
        synchronized(lock) {
            error = null
            publishLocked(force = true)
        }
    }

    /** Test seam: replaces the manifest repository created by [initialize]. */
    internal fun installArtifactRepository(repository: CaptureArtifactRepository?) {
        synchronized(lock) {
            artifactRepository = repository
        }
    }

    /** Start-of-capture manifest: always unfinalized, best-effort, never fatal. */
    private fun writeUnfinalizedArtifactsLocked() {
        val manifest = buildManifestLocked() ?: return
        val repository = artifactRepository ?: return
        runCatching { repository.writeUnfinalized(manifest) }
    }

    /**
     * Commits or refreshes the manifest at capture end. `complete = true` is only
     * written when the writers drained, nothing was dropped, no I/O error occurred
     * and the run was not interrupted; any failure refreshes the unfinalized view
     * instead, so a broken writer can never be published as a complete capture.
     */
    private fun commitArtifactsLocked() {
        val manifest = buildManifestLocked() ?: return
        val repository = artifactRepository ?: return
        val complete = writersDrained && !incomplete && !interrupted &&
            droppedPacketCount == 0L && ioErrorCount == 0L
        runCatching {
            if (complete) repository.commit(manifest.copy(complete = true))
            else repository.writeUnfinalized(manifest)
        }.onFailure {
            runCatching { repository.writeUnfinalized(manifest.copy(finalized = false, complete = false)) }
        }
    }

    /**
     * Frames are counted from the real persisted `packetCount`, never from
     * `offeredPacketCount`: a packet that was offered but not written to disk must
     * not occupy a frame number. The TLS block and retention policy come from the
     * caller, so PCAP completeness never asserts decryption completeness.
     */
    private fun buildManifestLocked(): CaptureArtifactManifest? {
        val config = manifestConfig ?: return null
        val repository = artifactRepository ?: return null
        val segments = ArrayList<CaptureSegmentRef>(segmentRecords.size)
        for ((index, record) in segmentRecords.withIndex()) {
            val start = record.startedAtPacketCount.coerceIn(0L, packetCount)
            val end = segmentRecords.getOrNull(index + 1)?.startedAtPacketCount?.coerceIn(0L, packetCount) ?: packetCount
            val relative = try {
                repository.relativeSegmentFile(config.captureId, File(record.path))
            } catch (_: TlsAssetException) {
                return null
            }
            segments += CaptureSegmentRef(
                file = relative,
                firstGlobalFrame = start + 1L,
                frameCount = (end - start).coerceAtLeast(0L)
            )
        }
        return CaptureArtifactManifest(
            captureId = config.captureId,
            captureMode = config.captureMode,
            packetVantage = config.packetVantage,
            segments = segments,
            packetDrops = droppedPacketCount,
            interrupted = interrupted,
            secretsPersistedSequence = secretsPersistedSequence,
            retentionPolicy = config.retentionPolicy,
            tls = config.tls
        )
    }

    private fun publishLocked(force: Boolean) {
        val now = System.currentTimeMillis()
        if (!force && now - lastPublishedAtMillis < UI_UPDATE_INTERVAL_MILLIS) return
        lastPublishedAtMillis = now
        _state.value = LiveCaptureState(
            isCapturing = capturing,
            startedAtMillis = startedAtMillis,
            stoppedAtMillis = stoppedAtMillis,
            packetCount = packetCount,
            byteCount = byteCount,
            offeredPacketCount = offeredPacketCount,
            droppedPacketCount = droppedPacketCount,
            ioErrorCount = ioErrorCount,
            lastIoError = lastIoError,
            outputPath = outputPath,
            segmentPaths = segmentRecords.map { it.path },
            interrupted = interrupted,
            incomplete = incomplete,
            error = error,
            recentPackets = recentPackets.toList()
        )
        persistLocked(force = force)
    }

    private fun persistLocked(force: Boolean) {
        val store = preferences ?: return
        val now = System.currentTimeMillis()
        if (!force && now - lastPersistedAtMillis < 1_000L) return
        lastPersistedAtMillis = now
        val json = JSONObject()
            .put("capturing", capturing)
            .put("interrupted", interrupted)
            .put("incomplete", incomplete)
            .put("startedAtMillis", startedAtMillis)
            .put("stoppedAtMillis", stoppedAtMillis)
            .put("packetCount", packetCount)
            .put("byteCount", byteCount)
            .put("offeredPacketCount", offeredPacketCount)
            .put("droppedPacketCount", droppedPacketCount)
            .put("ioErrorCount", ioErrorCount)
            .put("lastIoError", lastIoError ?: JSONObject.NULL)
            .put("outputPath", outputPath ?: JSONObject.NULL)
            .put("captureId", captureId ?: JSONObject.NULL)
            .put("segmentPaths", JSONArray(segmentRecords.map { it.path }))
            .put("error", error ?: JSONObject.NULL)
        store.edit().putString("state", json.toString()).apply()
    }

    private fun writeInterruptedReport() {
        val capture = outputPath?.let(::File)?.takeIf(File::isFile) ?: return
        val report = File(capture.parentFile, "${capture.name}.report.json")
        if (report.isFile) return
        runCatching {
            report.writeText(
                JSONObject()
                    .put("captureFile", capture.name)
                    .put("segments", JSONArray(segmentRecords.map { File(it.path).name }))
                    .put("startedAtMillis", startedAtMillis)
                    .put("stoppedAtMillis", System.currentTimeMillis())
                    .put("offeredPackets", offeredPacketCount)
                    .put("writtenPackets", packetCount)
                    .put("writtenBytes", byteCount)
                    .put("droppedPackets", droppedPacketCount)
                    .put("ioErrors", ioErrorCount)
                    .put("complete", false)
                    .put("stopReason", "process_interrupted")
                    .toString(2)
            )
        }
    }

    private fun JSONObject.optNullableString(name: String): String? =
        if (!has(name) || isNull(name)) null else optString(name).ifBlank { null }

    /** One PCAP segment and the persisted-frame count that preceded it. */
    private data class SegmentRecord(val path: String, val startedAtPacketCount: Long)

    internal fun parsePreview(number: Long, timestampMillis: Long, bytes: ByteArray, length: Int): LiveCapturePacketPreview {
        val safeLength = length.coerceIn(0, bytes.size)
        val version = if (safeLength > 0) (bytes[0].toInt() ushr 4) and 0x0f else 0
        return when (version) {
            4 -> parseIpv4(number, timestampMillis, bytes, safeLength)
            6 -> parseIpv6(number, timestampMillis, bytes, safeLength)
            else -> LiveCapturePacketPreview(number, timestampMillis, safeLength, version, "IP", "unknown", "unknown")
        }
    }

    private fun parseIpv4(number: Long, timestampMillis: Long, bytes: ByteArray, length: Int): LiveCapturePacketPreview {
        if (length < 20) return LiveCapturePacketPreview(number, timestampMillis, length, 4, "IPv4", "truncated", "truncated")
        val protocol = protocolName(bytes[9].toInt() and 0xff)
        val source = (12..15).joinToString(".") { (bytes[it].toInt() and 0xff).toString() }
        val destination = (16..19).joinToString(".") { (bytes[it].toInt() and 0xff).toString() }
        return LiveCapturePacketPreview(number, timestampMillis, length, 4, protocol, source, destination)
    }

    private fun parseIpv6(number: Long, timestampMillis: Long, bytes: ByteArray, length: Int): LiveCapturePacketPreview {
        if (length < 40) return LiveCapturePacketPreview(number, timestampMillis, length, 6, "IPv6", "truncated", "truncated")
        val protocol = protocolName(bytes[6].toInt() and 0xff)
        val source = formatIpv6(bytes, 8)
        val destination = formatIpv6(bytes, 24)
        return LiveCapturePacketPreview(number, timestampMillis, length, 6, protocol, source, destination)
    }

    private fun formatIpv6(bytes: ByteArray, start: Int): String {
        return (0 until 8).joinToString(":") { group ->
            val index = start + group * 2
            val value = ((bytes[index].toInt() and 0xff) shl 8) or (bytes[index + 1].toInt() and 0xff)
            value.toString(16)
        }
    }

    private fun protocolName(number: Int): String = when (number) {
        1 -> "ICMP"
        6 -> "TCP"
        17 -> "UDP"
        58 -> "ICMPv6"
        else -> "IP-$number"
    }
}
