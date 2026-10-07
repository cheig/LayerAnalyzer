package com.example.layanalyzer.capture

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
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
    private val segmentPaths = mutableListOf<String>()
    private var interrupted = false
    private var incomplete = false
    private var preferences: android.content.SharedPreferences? = null
    private var lastPersistedAtMillis = 0L
    private var error: String? = null
    private var lastPublishedAtMillis = 0L

    fun initialize(context: Context) {
        synchronized(lock) {
            if (preferences != null) return
            preferences = context.applicationContext.getSharedPreferences("live_capture_state", Context.MODE_PRIVATE)
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
                segmentPaths.clear()
                json.optJSONArray("segmentPaths")?.let { array -> for (i in 0 until array.length()) array.optString(i).takeIf(String::isNotBlank)?.let(segmentPaths::add) }
                error = if (interrupted) "Capture process was interrupted; evidence is incomplete." else json.optNullableString("error")
                if (interrupted) writeInterruptedReport()
                publishLocked(force = true)
                persistLocked(force = true)
            }
        }
    }

    fun start(outputPath: String) {
        synchronized(lock) {
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
            segmentPaths.clear()
            segmentPaths += outputPath
            interrupted = false
            incomplete = false
            error = null
            recentPackets.clear()
            publishLocked(force = true)
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
            if (path !in segmentPaths) segmentPaths += path
            publishLocked(force = true)
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
            interrupted = false
            incomplete = false
            publishLocked(force = true)
        }
    }

    fun fail(message: String) {
        synchronized(lock) {
            capturing = false
            stoppedAtMillis = System.currentTimeMillis()
            error = message
            interrupted = false
            incomplete = true
            publishLocked(force = true)
        }
    }

    fun clearError() {
        synchronized(lock) {
            error = null
            publishLocked(force = true)
        }
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
            segmentPaths = segmentPaths.toList(),
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
            .put("segmentPaths", JSONArray(segmentPaths))
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
                    .put("segments", JSONArray(segmentPaths.map { File(it).name }))
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
