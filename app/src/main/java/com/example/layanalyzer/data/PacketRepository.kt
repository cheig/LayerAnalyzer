// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.NativeEngine
import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.ConversationStat
import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.CoreSignalMessage
import com.example.layanalyzer.model.RtpHeuristicResult
import com.example.layanalyzer.model.RtpPacketMetric
import com.example.layanalyzer.model.RtcpPacketMetric
import com.example.layanalyzer.model.SdpMediaDirection
import com.example.layanalyzer.model.SdpMediaSummary
import com.example.layanalyzer.model.SdpOfferAnswerRole
import com.example.layanalyzer.model.SdpPayloadMapping
import com.example.layanalyzer.model.SipMessage
import com.example.layanalyzer.model.SipMessageFieldPresence
import com.example.layanalyzer.model.DecodeAsRule
import com.example.layanalyzer.model.DisplayFilterResult
import com.example.layanalyzer.model.EndpointStat
import com.example.layanalyzer.model.EspDecryptionMode
import com.example.layanalyzer.model.EspDecryptionResult
import com.example.layanalyzer.model.ExpertInfoItem
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.FileSessionInfo
import com.example.layanalyzer.model.FollowStreamRecord
import com.example.layanalyzer.model.FollowStreamResult
import com.example.layanalyzer.model.HttpObjectEntry
import com.example.layanalyzer.model.IoBucket
import com.example.layanalyzer.model.PacketSearchMode
import com.example.layanalyzer.model.PacketLengthBucket
import com.example.layanalyzer.model.PacketLengthStats
import com.example.layanalyzer.model.PacketFollowFilters
import com.example.layanalyzer.model.PacketSummary
import com.example.layanalyzer.model.ProtocolStat
import com.example.layanalyzer.model.ProtocolNode
import com.example.layanalyzer.model.ProtocolSummaryItem
import com.example.layanalyzer.model.RequestResponseTransaction
import com.example.layanalyzer.model.SummaryCacheStats
import com.example.layanalyzer.model.TimeDisplayFormat
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.OutputStream
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

class PacketRepository(
    private val rtpMediaCacheProvider: () -> RtpMediaCache? = { null }
) : CaptureSessionDataSource, AgentReadSession, PacketPageReader {
    @Volatile
    private var sessionPtr: Long = 0
    @Volatile
    private var currentFile: FileSessionInfo? = null
    private var firstPacketTimestamp: Double = 0.0
    private var timeDisplayFormat: TimeDisplayFormat = TimeDisplayFormat.Relative
    private var activeDisplayFilter: String = ""
    private val appliedDecodeAsEntries = mutableSetOf<Pair<String, Int>>()

    @Synchronized
    fun openFile(
        path: String,
        displayName: String = File(path).name,
        sizeBytes: Long = File(path).length(),
        onProgress: ((framesIndexed: Int, bytesRead: Long, totalBytes: Long) -> Boolean)? = null
    ): Result<FileSessionInfo> {
        closeFile()

        val ptr = NativeEngine.openFile(path) { framesIndexed, bytesRead, totalBytes ->
            onProgress?.invoke(framesIndexed, bytesRead, totalBytes) ?: true
        }

        if (ptr == 0L) {
            return Result.failure(
                IllegalStateException(NativeEngine.getLastError().ifBlank { "Failed to open capture file." })
            )
        }

        sessionPtr = ptr
        val info = FileSessionInfo(
            displayName = displayName,
            sizeBytes = sizeBytes,
            fileType = detectFileType(path),
            frameCount = NativeEngine.getFrameCount(ptr),
            localPath = path,
            encapsulation = NativeEngine.getCaptureEncapsulation(ptr)
        )
        currentFile = info
        activeDisplayFilter = ""
        firstPacketTimestamp = getRawPacketSummaries(0, 1).firstOrNull()?.time?.toDoubleOrNull() ?: 0.0
        return Result.success(info)
    }

    @Synchronized
    fun closeFile() {
        // Cancellation is lock-free on the native side. Signal it before
        // closeFile waits for the session lifetime write lock.
        NativeEngine.cancelLongRunningOperations()
        resetAppliedDecodeAsRules()
        val closingSession = sessionPtr
        if (closingSession != 0L) {
            NativeEngine.closeFile(closingSession)
            sessionPtr = 0
            rtpMediaCacheProvider()?.deleteSession(closingSession)
        }
        currentFile = null
        firstPacketTimestamp = 0.0
        activeDisplayFilter = ""
    }

    override fun currentFile(): FileSessionInfo? = currentFile

    override fun currentSessionHandle(): Long = sessionPtr

    override fun cancelLongRunningOperations() {
        NativeEngine.cancelLongRunningOperations()
    }

    fun cancelSearch() {
        if (sessionPtr != 0L) NativeEngine.cancelSearch(sessionPtr)
    }

    override fun getFrameCount(): Int = if (sessionPtr == 0L) 0 else NativeEngine.getFrameCount(sessionPtr)

    override fun getVisibleFrameCount(): Int = if (sessionPtr == 0L) 0 else NativeEngine.getFilteredFrameCount(sessionPtr)

    override fun getAppliedDisplayFilter(): String = activeDisplayFilter

    fun getVisiblePacketSummary(index: Int): PacketSummary? {
        if (index !in 0 until getVisibleFrameCount()) return null
        return getPacketSummaries(index, 1).firstOrNull()
    }

    fun findVisibleFramePosition(frameNumber: Long): Int? {
        var low = 0
        var high = getVisibleFrameCount() - 1
        while (low <= high) {
            val middle = low + (high - low) / 2
            val middleFrame = getVisiblePacketSummary(middle)?.frameNumber ?: return null
            when {
                middleFrame < frameNumber -> low = middle + 1
                middleFrame > frameNumber -> high = middle - 1
                else -> return middle
            }
        }
        return null
    }

    override fun getPacketSummaries(start: Int, count: Int): List<PacketSummary> {
        if (timeDisplayFormat == TimeDisplayFormat.Delta) {
            val rawStart = (start - 1).coerceAtLeast(0)
            val raw = getRawPacketSummaries(rawStart, count + if (start > 0) 1 else 0)
            return raw.drop(if (start > 0) 1 else 0).mapIndexed { index, summary ->
                val rawIndex = index + if (start > 0) 1 else 0
                val timestamp = summary.time.toDoubleOrNull() ?: 0.0
                val previous = raw.getOrNull(rawIndex - 1)?.time?.toDoubleOrNull() ?: timestamp
                summary.copy(time = String.format(Locale.US, "+%.6f", timestamp - previous))
            }
        }
        return getRawPacketSummaries(start, count).map { summary ->
            summary.copy(time = formatPacketTime(summary.time.toDoubleOrNull() ?: 0.0))
        }
    }

    fun getSummaryCacheStats(): SummaryCacheStats {
        if (sessionPtr == 0L) return SummaryCacheStats()
        val json = JSONObject(NativeEngine.getSummaryCacheStats(sessionPtr))
        return SummaryCacheStats(
            frames = json.optInt("frames", 0),
            valid = json.optInt("valid", 0),
            hits = json.optLong("hits", 0L),
            misses = json.optLong("misses", 0L)
        )
    }

    override fun getFirstPacketTimestamp(): Double = firstPacketTimestamp

    override fun getRawPacketSummaries(start: Int, count: Int): List<PacketSummary> {        if (sessionPtr == 0L || start < 0 || count <= 0) return emptyList()
        val coreSummaries = NativeEngine.getPacketSummaries(sessionPtr, start, count)
        return coreSummaries.map { core ->
            PacketSummary(
                frameNumber = core.num.toLong(),
                time = String.format(Locale.US, "%.6f", core.time),
                source = core.source,
                destination = core.destination,
                protocol = core.protocol,
                length = core.length,
                sourcePort = core.sourcePort.takeIf { it >= 0 },
                destinationPort = core.destinationPort.takeIf { it >= 0 },
                info = core.info
            )
        }
    }

    /**
     * Read a page through the Native Scoped Query API when the loaded JNI
     * library provides it.  A null result means the symbol is unavailable or
     * the response could not be decoded, which lets the Agent repository use
     * its Filter Lease compatibility path.
     */
    override fun queryPacketSummariesScoped(
        filter: String,
        start: Int,
        count: Int
    ): ScopedPacketSummaryQuery? {
        if (sessionPtr == 0L || start < 0 || count <= 0) return null
        val boundedCount = count.coerceIn(1, 100)
        val response = runCatching {
            NativeEngine.queryPacketSummaries(
                sessionPtr = sessionPtr,
                displayFilter = filter.trim(),
                start = start,
                count = boundedCount
            )
        }.getOrNull() ?: return null
        return runCatching { parseScopedPacketSummaryQuery(JSONObject(response), start) }
            .getOrNull()
    }

    /** Kept internal so the Native/Kotlin JSON contract can be tested without JNI. */
    internal fun parseScopedPacketSummaryQuery(
        json: JSONObject,
        requestedOffset: Int = 0
    ): ScopedPacketSummaryQuery {
        val itemsJson = json.optJSONArray("items")
        val items = buildList {
            if (itemsJson != null) {
                for (index in 0 until itemsJson.length()) {
                    val item = itemsJson.optJSONObject(index) ?: continue
                    add(
                        PacketSummary(
                            frameNumber = item.optLong("frameNumber", item.optLong("num")),
                            time = String.format(
                                Locale.US,
                                "%.6f",
                                item.optDouble("time", item.optDouble("timestamp", 0.0))
                            ),
                            source = item.optString("source"),
                            destination = item.optString("destination"),
                            protocol = item.optString("protocol"),
                            length = item.optInt("length", 0),
                            sourcePort = item.optInt("sourcePort", -1).takeIf { it >= 0 },
                            destinationPort = item.optInt("destinationPort", -1)
                                .takeIf { it >= 0 },
                            info = item.optString("info")
                        )
                    )
                }
            }
        }
        val offset = json.optInt("offset", requestedOffset).coerceAtLeast(0)
        return ScopedPacketSummaryQuery(
            success = json.optBoolean("success", false),
            error = json.optString("error").ifBlank { null },
            items = items,
            offset = offset,
            returned = json.optInt("returned", items.size).coerceAtLeast(0),
            total = json.optInt("total", items.size).coerceAtLeast(0),
            truncated = json.optBoolean("truncated", false),
            cancelled = json.optBoolean("cancelled", false),
            queryVersion = json.optString("queryVersion")
        )
    }

    fun setTimeDisplayFormat(format: TimeDisplayFormat) {
        timeDisplayFormat = format
    }

    override fun getPacketDetails(frameNumber: Long): ProtocolNode? {
        if (sessionPtr == 0L) return null
        val index = (frameNumber - 1).toInt()
        val jsonString = NativeEngine.getPacketDetails(sessionPtr, index)
        if (jsonString.isEmpty()) return null

        return try {
            parseProtocolNode(JSONObject(jsonString))
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    fun getPacketFollowFilters(frameNumber: Long): PacketFollowFilters {
        val root = getPacketDetails(frameNumber)
            ?: throw IllegalStateException("Packet details are not available.")
        return PacketFollowFilters(
            sipCall = root.findDisplayFilter("sip.Call-ID"),
            udpStream = root.findDisplayFilter("udp.stream"),
            tcpStream = root.findDisplayFilter("tcp.stream")
        )
    }

    fun getPacketBytes(frameNumber: Long): ByteArray {
        if (sessionPtr == 0L) return ByteArray(0)
        return NativeEngine.getPacketBytes(sessionPtr, (frameNumber - 1).toInt())
    }

    fun getHttpObjects(): List<HttpObjectEntry> {
        if (sessionPtr == 0L) throw IllegalStateException("No capture is open.")
        val json = JSONObject(NativeEngine.getHttpObjects(sessionPtr))
        json.optString("error").takeIf { it.isNotBlank() }?.let { throw IllegalStateException(it) }
        val objects = json.optJSONArray("objects") ?: return emptyList()
        return buildList {
            for (index in 0 until objects.length()) {
                val item = objects.getJSONObject(index)
                add(
                    HttpObjectEntry(
                        id = item.optInt("id", index),
                        frameNumber = item.optLong("frameNumber"),
                        hostname = item.optString("hostname"),
                        contentType = item.optString("contentType")
                            .substringBefore(';')
                            .trim()
                            .ifBlank { "application/octet-stream" },
                        filename = item.optString("filename")
                            .ifBlank { "http-object-${item.optLong("frameNumber")}-${index + 1}" },
                        size = item.optLong("size")
                    )
                )
            }
        }
    }

    fun getHttpObjectPayload(objectId: Int): ByteArray {
        if (sessionPtr == 0L) throw IllegalStateException("No capture is open.")
        return NativeEngine.getHttpObjectPayload(sessionPtr, objectId)
    }

    @Synchronized
    override fun applyDisplayFilter(
        filter: String,
        expectedSessionHandle: Long
    ): DisplayFilterResult {
        if (sessionPtr == 0L || sessionPtr != expectedSessionHandle) {
            return DisplayFilterResult(success = false, filteredCount = 0, error = "No capture is open.")
        }
        val json = JSONObject(NativeEngine.applyDisplayFilter(sessionPtr, filter.trim()))
        val success = json.optBoolean("success", false)
        val error = json.optString("error").ifBlank { null }
        val count = json.optInt("count", getVisibleFrameCount())
        if (success) activeDisplayFilter = filter.trim()
        return DisplayFilterResult(success = success, filteredCount = count, error = error)
    }

    /** Backward-compatible entry point for non-coordinated legacy callers. */
    fun applyDisplayFilter(filter: String): DisplayFilterResult =
        applyDisplayFilter(filter, sessionPtr)

    override fun validateDisplayFilter(filter: String): Result<Unit> {
        if (sessionPtr == 0L) return Result.failure(IllegalStateException("No capture is open."))
        val json = JSONObject(NativeEngine.validateDisplayFilter(sessionPtr, filter.trim()))
        return if (json.optBoolean("success", false)) {
            Result.success(Unit)
        } else {
            Result.failure(IllegalArgumentException(json.optString("error").ifBlank { "Invalid display filter." }))
        }
    }

    fun searchPackets(mode: PacketSearchMode, query: String): List<Long> {
        if (sessionPtr == 0L || query.isBlank()) return emptyList()
        return NativeEngine.searchPackets(sessionPtr, mode.nativeName, query.trim()).map { it.toLong() }
    }

    override fun searchPacketFrames(mode: PacketSearchMode, query: String): List<Long> =
        searchPackets(mode, query)

    override fun getExpertInfoSummary(): ExpertInfoSummary {
        if (sessionPtr == 0L) return ExpertInfoSummary()
        val json = JSONObject(NativeEngine.getExpertInfoSummary(sessionPtr))
        val items = json.optJSONArray("items").toExpertItems()
        return ExpertInfoSummary(
            warningPackets = json.optInt("warnings", 0),
            errorPackets = json.optInt("errors", 0),
            items = items,
            totalItems = json.optInt("totalItems", items.size),
            truncated = json.optBoolean("truncated", false)
        )
    }

    override fun followStream(frameNumber: Long, protocol: String): FollowStreamResult {
        if (sessionPtr == 0L) {
            return FollowStreamResult(protocol = protocol, streamId = -1, records = emptyList(), error = "No capture is open.")
        }
        val json = JSONObject(NativeEngine.followStream(sessionPtr, (frameNumber - 1).toInt(), protocol.lowercase()))
        val recordsJson = json.optJSONArray("records")
        val records = buildList {
            if (recordsJson != null) {
                for (i in 0 until recordsJson.length()) {
                    val item = recordsJson.getJSONObject(i)
                    add(
                        FollowStreamRecord(
                            frameNumber = item.optLong("frameNumber"),
                            direction = item.optString("direction"),
                            source = item.optString("source"),
                            destination = item.optString("destination"),
                            length = item.optInt("length"),
                            payload = item.optBoolean("payload", false),
                            text = item.optString("text", item.optString("ascii")),
                            ascii = item.optString("ascii"),
                            hex = item.optString("hex")
                        )
                    )
                }
            }
        }
        return FollowStreamResult(
            protocol = json.optString("protocol", protocol),
            streamId = json.optInt("streamId", -1),
            records = records,
            scope = json.optString("scope", "current filtered packet set"),
            directionKnown = json.optBoolean("directionKnown", false),
            error = json.optString("error").ifBlank { null }
        )
    }

    fun setNameResolutionEnabled(enabled: Boolean) {
        if (sessionPtr != 0L) NativeEngine.setNameResolutionEnabled(sessionPtr, enabled)
    }

    /**
     * Enables/disables the process-wide RTP heuristics (RTP1-KT-03).
     *
     * Unlike name resolution this is not session-scoped: like Decode As it is a
     * process-wide native setting, so it must not be keyed on [sessionPtr].
     */
    fun setRtpHeuristicEnabled(enabled: Boolean): RtpHeuristicResult {
        val root = runCatching { JSONObject(NativeEngine.setRtpHeuristicEnabled(enabled)) }.getOrNull()
            ?: return RtpHeuristicResult(enabled = enabled, error = "Malformed RTP heuristic response.")
        return RtpHeuristicResult(
            enabled = root.optBoolean("enabled", enabled),
            error = root.optString("error", "")
        )
    }

    /**
     * Applies the process-wide ESP NULL-encryption decryption policy.
     *
     * `Probe` has to sample the open capture, so [sessionPtr] is handed in; with
     * no capture open the native side probes nothing and reports
     * `enabled = false`. Like the RTP heuristics this is a process-wide native
     * setting, so the reply — not the request — decides the effective state.
     */
    fun setEspDecryptionMode(mode: EspDecryptionMode): EspDecryptionResult {
        val root = runCatching {
            JSONObject(NativeEngine.setEspDecryptionMode(sessionPtr, mode.nativeValue))
        }.getOrNull() ?: return EspDecryptionResult(
            mode = mode,
            enabled = false,
            decoded = false,
            framesScanned = 0,
            error = "Malformed ESP decryption response."
        )
        return EspDecryptionResult(
            mode = mode,
            enabled = root.optBoolean("enabled", false),
            decoded = root.optBoolean("decoded", false),
            framesScanned = root.optInt("framesScanned", 0),
            error = root.optString("error", "")
        )
    }

    @Synchronized
    fun applyDecodeAsRule(
        rule: DecodeAsRule,
        expectedSessionHandle: Long = sessionPtr
    ): DisplayFilterResult {
        if (sessionPtr == 0L || sessionPtr != expectedSessionHandle) {
            return DisplayFilterResult(success = false, filteredCount = 0, error = "No capture is open.")
        }
        if (rule.protocol.isBlank() || rule.ports.isEmpty()) {
            return DisplayFilterResult(success = false, filteredCount = getVisibleFrameCount(), error = "Protocol and port are required.")
        }

        for (port in rule.ports) {
            val json = JSONObject(NativeEngine.applyDecodeAs(sessionPtr, rule.transport.nativeTable, port, rule.protocol.trim()))
            if (!json.optBoolean("success", false)) {
                return DisplayFilterResult(
                    success = false,
                    filteredCount = getVisibleFrameCount(),
                    error = json.optString("error").ifBlank { "Unable to apply Decode As rule." }
                )
            }
            appliedDecodeAsEntries += rule.transport.nativeTable to port
        }
        return DisplayFilterResult(success = true, filteredCount = getVisibleFrameCount())
    }

    @Synchronized
    fun resetDecodeAsRule(
        rule: DecodeAsRule,
        expectedSessionHandle: Long = sessionPtr
    ) {
        if (sessionPtr == 0L || sessionPtr != expectedSessionHandle) return
        rule.ports.forEach { port ->
            NativeEngine.resetDecodeAs(sessionPtr, rule.transport.nativeTable, port)
            appliedDecodeAsEntries -= rule.transport.nativeTable to port
        }
    }

    fun exportPacketDetailsText(frameNumber: Long, output: OutputStream) {
        val root = getPacketDetails(frameNumber) ?: throw IllegalStateException("Packet details are not available.")
        output.writer(Charsets.UTF_8).use { writer ->
            writer.appendLine("Packet $frameNumber")
            writer.appendLine()
            renderProtocolNode(root, writer::appendLine)
        }
    }

    fun exportPacketBytesHex(frameNumber: Long, range: IntRange?, output: OutputStream) {
        val bytes = getPacketBytes(frameNumber).selectedRange(range)
        output.writer(Charsets.UTF_8).use { writer ->
            var offset = range?.first?.coerceAtLeast(0) ?: 0
            bytes.asIterable().chunked(16).forEach { row ->
                val hex = row.joinToString(" ") { "%02X".format(it.toInt() and 0xff) }
                val ascii = row.joinToString("") { byte ->
                    val value = byte.toInt() and 0xff
                    if (value in 32..126) value.toChar().toString() else "."
                }
                writer.appendLine("%08X  %-47s  %s".format(offset, hex, ascii))
                offset += row.size
            }
        }
    }

    fun exportFilteredCapture(outputFile: File) {
        if (sessionPtr == 0L) throw IllegalStateException("No capture is open.")
        val result = JSONObject(NativeEngine.exportVisibleCapture(sessionPtr, outputFile.absolutePath))
        if (!result.optBoolean("success", false)) {
            throw IllegalStateException(result.optString("error").ifBlank { "Unable to export capture." })
        }
    }

    override fun buildCaptureStatistics(bucketSeconds: Double): CaptureStatistics {
        if (sessionPtr == 0L) return CaptureStatistics()
        val json = JSONObject(NativeEngine.buildStatistics(sessionPtr, bucketSeconds.coerceAtLeast(0.001)))
        if (json.optBoolean("cancelled", false)) {
            throw NativeOperationCancelledException()
        }
        json.optString("error").takeIf { it.isNotBlank() }?.let { throw IllegalStateException(it) }
        val statistics = parseCaptureStatistics(json)
        val transactions = buildRequestResponseTransactions(loadVisibleSummaries())
        return statistics.copy(
            dnsTransactions = transactions.first,
            httpTransactions = transactions.second
        )
    }

    fun buildCaptureStatistics(): CaptureStatistics = buildCaptureStatistics(1.0)

    /**
     * [PERF-export] T0 基线任务：G4 对拍结果导出（Debug 构建专用）。
     * 让 native 侧把过滤/搜索/统计/Expert/Follow Stream/HTTP 对象/可见帧 pcap
     * 一次性写到 [outputDir]。返回 native 结果 JSON；失败时 success=false。
     */
    fun exportPerfResults(outputDir: String): String {
        if (sessionPtr == 0L) return """{"success":false,"error":"No capture is open."}"""
        return NativeEngine.exportPerfResults(sessionPtr, outputDir)
    }

    override fun buildCommunicationAnalysis(): CommunicationAnalysis {
        if (sessionPtr == 0L) return CommunicationAnalysis()
        val json = JSONObject(NativeEngine.buildCommunicationAnalysis(sessionPtr))
        if (json.optBoolean("cancelled", false)) {
            throw NativeOperationCancelledException()
        }
        json.optString("error").takeIf { it.isNotBlank() }?.let { throw IllegalStateException(it) }
        return parseCommunicationAnalysis(json)
    }

    /** Kept internal so the Native/Kotlin contract can be verified without JNI. */
    internal fun parseCommunicationAnalysis(json: JSONObject): CommunicationAnalysis {
        val sipMessages = json.optJSONArray("sipMessages").mapObjects { item ->
            val cSeqNumber = item.optNullableLong("cSeqNumber")
            val cSeqMethod = item.optNullableString("cSeqMethod")
            val viaBranch = item.optNullableString("viaBranch")
            val fromTag = item.optNullableString("fromTag")
            val toTag = item.optNullableString("toTag")
            val requestUri = item.optNullableString("requestUri")
            val authorizationScheme = item.optNullableString("authorizationScheme")
            val contentType = item.optNullableString("contentType")
            SipMessage(
                frameNumber = item.optLong("frameNumber"),
                time = item.optDouble("time"),
                source = item.optString("source"),
                destination = item.optString("destination"),
                sourcePort = item.optInt("sourcePort").takeIf { it >= 0 },
                destinationPort = item.optInt("destinationPort").takeIf { it >= 0 },
                method = item.optString("method"),
                status = item.optString("status"),
                callId = item.optString("callId"),
                cSeqNumber = cSeqNumber,
                cSeqMethod = cSeqMethod,
                viaBranch = viaBranch,
                fromTag = fromTag,
                toTag = toTag,
                requestUri = requestUri,
                authorizationPresent = item.optBoolean("authorizationPresent", item.optBoolean("hasAuthorization")),
                authorizationScheme = authorizationScheme,
                contentType = contentType,
                fieldPresence = SipMessageFieldPresence(
                    cSeqNumber = item.optBoolean("hasCSeqNumber", cSeqNumber != null),
                    cSeqMethod = item.optBoolean("hasCSeqMethod", cSeqMethod != null),
                    viaBranch = item.optBoolean("hasViaBranch", viaBranch != null),
                    fromTag = item.optBoolean("hasFromTag", fromTag != null),
                    toTag = item.optBoolean("hasToTag", toTag != null),
                    requestUri = item.optBoolean("hasRequestUri", requestUri != null),
                    authorization = item.optBoolean("hasAuthorization", item.optBoolean("authorizationPresent")),
                    contentType = item.optBoolean("hasContentType", contentType != null),
                    sdpDirection = item.optBoolean("hasSdpDirection", item.has("sdpDirection") && !item.isNull("sdpDirection")),
                    sdpPayloadMappings = item.optBoolean(
                        "hasSdpPayloadMappings",
                        (item.optJSONArray("sdpPayloadMappings")?.length() ?: 0) > 0
                    ),
                    sdpOfferAnswerRole = item.optBoolean("hasSdpOfferAnswerRole", item.has("sdpOfferAnswerRole"))
                ),
                info = item.optString("info"),
                sdp = if (item.optBoolean("hasSdp")) {
                    SdpMediaSummary(
                        frameNumber = item.optLong("frameNumber"),
                        connectionAddress = item.optString("sdpConnectionAddress"),
                        mediaType = item.optString("sdpMediaType"),
                        mediaPort = item.optInt("sdpMediaPort").takeIf { it >= 0 },
                        mediaProtocol = item.optString("sdpMediaProtocol"),
                        formats = item.optJSONArray("sdpFormats").toStringList(),
                        codecs = item.optJSONArray("sdpCodecs").toStringList(),
                        direction = SdpMediaDirection.fromWire(item.optNullableString("sdpDirection")),
                        payloadMappings = item.optJSONArray("sdpPayloadMappings").mapObjects { mapping ->
                            SdpPayloadMapping(
                                payloadType = mapping.optNullableInt("payloadType"),
                                encodingName = mapping.optString("encodingName"),
                                clockRate = mapping.optNullableInt("clockRate"),
                                channels = mapping.optNullableInt("channels"),
                                fmtpParameters = mapping.optJSONArray("fmtpParameters").toStringList()
                            )
                        },
                        offerAnswerRole = SdpOfferAnswerRole.fromWire(
                            item.optNullableString("sdpOfferAnswerRole")
                        )
                    )
                } else null
            )
        }
        val rtpPackets = json.optJSONArray("rtpPackets").mapObjects { item ->
            RtpPacketMetric(
                frameNumber = item.optLong("frameNumber"),
                time = item.optDouble("time"),
                source = item.optString("source"),
                destination = item.optString("destination"),
                sourcePort = item.optInt("sourcePort").takeIf { it >= 0 },
                destinationPort = item.optInt("destinationPort").takeIf { it >= 0 },
                sequence = item.optInt("sequence").takeIf { it >= 0 },
                ssrc = item.optLong("ssrc").takeIf { it >= 0 },
                timestamp = item.optLong("timestamp").takeIf { it >= 0 },
                payloadType = item.optInt("payloadType").takeIf { it >= 0 }
            )
        }
        val rtcpPackets = json.optJSONArray("rtcpPackets").mapObjects { item ->
            RtcpPacketMetric(
                frameNumber = item.optLong("frameNumber"),
                time = item.optDouble("time"),
                source = item.optString("source"),
                destination = item.optString("destination"),
                sourcePort = item.optInt("sourcePort").takeIf { it >= 0 },
                destinationPort = item.optInt("destinationPort").takeIf { it >= 0 },
                packetType = item.optInt("packetType").takeIf { it >= 0 },
                senderSsrc = item.optLong("senderSsrc").takeIf { it >= 0 },
                reportedSsrc = item.optLong("reportedSsrc").takeIf { it >= 0 },
                fractionLost = item.optInt("fractionLost").takeIf { it >= 0 },
                cumulativeLost = item.optInt("cumulativeLost").takeIf { it != Int.MIN_VALUE },
                interarrivalJitter = item.optLong("interarrivalJitter").takeIf { it >= 0 }
            )
        }
        val coreMessages = json.optJSONArray("coreMessages").mapObjects { item ->
            val fields = linkedMapOf<String, String>().apply {
                putAll(item.optStringMap("fields"))
                putAll(item.optStringMap("identifiers"))
                putAll(item.optStringMap("identifierFields"))
            }
            CoreSignalMessage(
                frameNumber = item.optLong("frameNumber"),
                time = item.optDouble("time"),
                protocol = item.optString("protocol"),
                source = item.optString("source"),
                destination = item.optString("destination"),
                correlationField = item.optString("correlationField"),
                correlationValue = item.optString("correlationValue"),
                messageType = item.optString("messageType"),
                outcome = item.optString("outcome"),
                info = item.optString("info"),
                procedureType = item.optString("procedureType"),
                commandCode = item.optNullableInt("commandCode"),
                applicationId = item.optNullableLong("applicationId"),
                request = item.optNullableBoolean("request"),
                resultCode = item.optString("resultCode"),
                experimentalResult = item.optString("experimentalResult"),
                originRealm = item.optString("originRealm"),
                destinationRealm = item.optString("destinationRealm"),
                sessionId = item.optString("sessionId"),
                sequenceNumber = item.optNullableLong("sequenceNumber"),
                cause = item.optString("cause"),
                nodeId = item.optString("nodeId"),
                teid = item.optString("teid"),
                seid = item.optString("seid"),
                ueId = item.optString("ueId"),
                ueIdType = item.optString("ueIdType"),
                procedureCode = item.optString("procedureCode"),
                bearerId = item.optString("bearerId"),
                procedureTransactionIdentity = item.optNullableInt("procedureTransactionIdentity"),
                registrationState = item.optString("registrationState"),
                sessionState = item.optString("sessionState"),
                subscriberId = item.optString("subscriberId"),
                apnOrDnn = item.optString("apnOrDnn"),
                explicitReference = item.optString("explicitReference"),
                fields = fields,
                fieldPresence = item.optJSONArray("fieldPresence").toStringList().toSet()
            )
        }
        return CommunicationAnalyzer.aggregate(
            CommunicationAnalysis(
                schemaVersion = json.optInt("schemaVersion", 1),
                sipMessages = sipMessages,
                sipTotal = json.optInt("sipTotal"),
                sipTruncated = json.optBoolean("sipTruncated"),
                rtpPackets = rtpPackets,
                rtpTotal = json.optInt("rtpTotal"),
                rtpTruncated = json.optBoolean("rtpTruncated"),
                rtcpPackets = rtcpPackets,
                rtcpTotal = json.optInt("rtcpTotal"),
                rtcpTruncated = json.optBoolean("rtcpTruncated"),
                coreMessages = coreMessages,
                coreTotal = json.optInt("coreTotal"),
                coreTruncated = json.optBoolean("coreTruncated")
            )
        )
    }

    private fun detectFileType(path: String): String {
        val name = File(path).name.lowercase()
        return when {
            name.endsWith(".pcapng") -> "pcapng"
            name.endsWith(".pcap") -> "pcap"
            else -> "capture"
        }
    }

    private fun formatPacketTime(timestamp: Double): String {
        return when (timeDisplayFormat) {
            TimeDisplayFormat.Relative -> String.format(Locale.US, "+%.6f", timestamp - firstPacketTimestamp)
            TimeDisplayFormat.Absolute -> runCatching {
                ABSOLUTE_TIME_FORMATTER.format(Instant.ofEpochSecond(timestamp.toLong(), ((timestamp % 1.0) * 1_000_000_000).toLong()))
            }.getOrDefault(String.format(Locale.US, "%.6f", timestamp))
            TimeDisplayFormat.Utc -> runCatching {
                UTC_TIME_FORMATTER.format(Instant.ofEpochSecond(timestamp.toLong(), ((timestamp % 1.0) * 1_000_000_000).toLong()))
            }.getOrDefault(String.format(Locale.US, "%.6f", timestamp))
            TimeDisplayFormat.Delta -> String.format(Locale.US, "+0.000000")
        }
    }

    private fun resetAppliedDecodeAsRules() {
        if (sessionPtr == 0L) return
        appliedDecodeAsEntries.toList().forEach { (table, port) ->
            NativeEngine.resetDecodeAs(sessionPtr, table, port)
        }
        appliedDecodeAsEntries.clear()
    }

    private fun renderProtocolNode(node: ProtocolNode, appendLine: (String) -> Unit, level: Int = 0) {
        val indent = "  ".repeat(level)
        val metadata = buildList {
            node.filter?.takeIf { it.isNotBlank() }?.let { add(it) }
            if (node.length > 0) add("bytes ${node.start}-${node.start + node.length - 1}")
            if (node.generated) add("generated")
            if (node.hidden) add("hidden")
            if (node.severity != "none") add(node.severity)
        }.joinToString(", ")
        appendLine("$indent${node.label}${if (metadata.isBlank()) "" else " [$metadata]"}")
        node.children.forEach { renderProtocolNode(it, appendLine, level + 1) }
    }

    internal fun parseProtocolNode(json: JSONObject): ProtocolNode {
        val label = json.optString("label", "Unknown")
        val value = json.optString("value")
        val start = json.optInt("start", 0)
        val length = json.optInt("length", 0)
        val filter = json.optString("filter", json.optString("id", ""))
        val filterValue = json.optString("filterValue")
        val severity = json.optString("severity", "none")
        val generated = json.optBoolean("generated", false)
        val hidden = json.optBoolean("hidden", false)

        val childrenJson = json.optJSONArray("children")
        val children = mutableListOf<ProtocolNode>()
        if (childrenJson != null) {
            for (i in 0 until childrenJson.length()) {
                children.add(parseProtocolNode(childrenJson.getJSONObject(i)))
            }
        }

        return ProtocolNode(
            label = label,
            value = if (value.isNotEmpty()) value else null,
            filter = filter.ifBlank { null },
            filterValue = filterValue.ifBlank { null },
            start = start,
            length = length,
            severity = severity,
            generated = generated,
            hidden = hidden,
            children = children
        )
    }

    private fun ProtocolNode.findDisplayFilter(fieldName: String): String? {
        if (filter.equals(fieldName, ignoreCase = true) && !filterValue.isNullOrBlank()) {
            return "$filter == $filterValue"
        }
        children.forEach { child ->
            child.findDisplayFilter(fieldName)?.let { return it }
        }
        return null
    }

    private fun loadVisibleSummaries(): List<PacketSummary> {
        val total = getVisibleFrameCount()
        if (total <= 0) return emptyList()
        val summaries = ArrayList<PacketSummary>(total)
        var start = 0
        while (start < total) {
            val chunk = getRawPacketSummaries(start, minOf(STATISTICS_BATCH_SIZE, total - start))
            if (chunk.isEmpty()) break
            summaries.addAll(chunk)
            start += chunk.size
        }
        return summaries
    }

    private fun buildRequestResponseTransactions(
        summaries: List<PacketSummary>
    ): Pair<List<RequestResponseTransaction>, List<RequestResponseTransaction>> {
        val dnsMessages = mutableListOf<TransactionMessage>()
        val httpMessages = mutableListOf<TransactionMessage>()
        summaries.forEach { summary ->
            val protocol = summary.protocol.uppercase()
            val info = summary.info.uppercase()
            val mayBeDns = protocol.contains("DNS") || info.contains("STANDARD QUERY")
            val mayBeHttp = protocol.startsWith("HTTP") || HTTP_METHODS.any { info.startsWith(it) } || info.startsWith("HTTP/")
            if (!mayBeDns && !mayBeHttp) return@forEach
            val root = runCatching { getPacketDetails(summary.frameNumber) }.getOrNull() ?: return@forEach
            if (mayBeDns) buildDnsMessage(summary, root)?.let(dnsMessages::add)
            if (mayBeHttp) buildHttpMessage(summary, root)?.let(httpMessages::add)
        }
        return pairMessages(dnsMessages) to pairMessages(httpMessages)
    }

    private fun buildDnsMessage(summary: PacketSummary, root: ProtocolNode): TransactionMessage? {
        val transactionId = root.firstRawFieldValue("dns.id") ?: return null
        val responseFlag = root.firstRawFieldValue("dns.flags.response")
        val isResponse = when (responseFlag?.trim()?.lowercase()) {
            "1", "true" -> true
            "0", "false" -> false
            else -> summary.info.contains("response", ignoreCase = true)
        }
        val queryName = root.firstDisplayFieldValue("dns.qry.name")
        val queryType = root.firstDisplayFieldValue("dns.qry.type")
        val queryText = listOfNotNull(queryType, queryName).joinToString(" ").ifBlank {
            summary.info.ifBlank { "DNS query $transactionId" }
        }
        val responseCode = root.firstDisplayFieldValue("dns.flags.rcode")
        val answers = root.collectDisplayFieldValues(DNS_ANSWER_FIELDS).distinct().take(DNS_ANSWER_LIMIT)
        val responseText = buildList {
            responseCode?.let { add(it) }
            addAll(answers)
        }.joinToString("; ").ifBlank { summary.info.ifBlank { "DNS response $transactionId" } }
        val linkedFrame = root.firstFrameNumber(
            if (isResponse) "dns.response_to" else "dns.response_in"
        )
        return TransactionMessage(
            protocol = "DNS",
            frameNumber = summary.frameNumber,
            time = summary.timeAsDouble(),
            source = summary.sourceEndpoint(),
            destination = summary.destinationEndpoint(),
            key = "dns:$transactionId:${summary.normalizedFlowKey()}",
            isResponse = isResponse,
            linkedFrame = linkedFrame,
            text = if (isResponse) responseText else queryText
        )
    }

    private fun buildHttpMessage(summary: PacketSummary, root: ProtocolNode): TransactionMessage? {
        val method = root.firstDisplayFieldValue("http.request.method", "http2.headers.method")
        val status = root.firstDisplayFieldValue("http.response.code", "http2.headers.status")
        val hasRequest = method != null || root.hasAnyField("http.request")
        val hasResponse = status != null || root.hasAnyField("http.response")
        if (!hasRequest && !hasResponse) return null
        val isResponse = hasResponse && !hasRequest
        val isHttp2 = root.hasAnyField("http2.streamid", "http2.headers.method", "http2.headers.status")
        val stream = root.firstRawFieldValue("tcp.stream") ?: summary.normalizedFlowKey()
        val http2Stream = root.firstRawFieldValue("http2.streamid")
        val authority = root.firstDisplayFieldValue("http2.headers.authority", "http.host")
        val path = root.firstDisplayFieldValue("http.request.full_uri", "http2.headers.path", "http.request.uri")
        val requestTarget = when {
            path.isNullOrBlank() -> authority
            path.startsWith("http://", true) || path.startsWith("https://", true) -> path
            authority.isNullOrBlank() -> path
            else -> authority + path
        }
        val requestText = listOfNotNull(method, requestTarget).joinToString(" ").ifBlank {
            summary.info.ifBlank { "HTTP request" }
        }
        val phrase = root.firstDisplayFieldValue("http.response.phrase")
        val responseText = listOfNotNull(status, phrase).joinToString(" ").ifBlank {
            summary.info.ifBlank { "HTTP response" }
        }
        val linkedFrame = root.firstFrameNumber(
            if (isResponse) "http.request_in" else "http.response_in"
        )
        return TransactionMessage(
            protocol = if (isHttp2) "HTTP/2" else "HTTP",
            frameNumber = summary.frameNumber,
            time = summary.timeAsDouble(),
            source = summary.sourceEndpoint(),
            destination = summary.destinationEndpoint(),
            key = "http:$stream:${http2Stream.orEmpty()}",
            isResponse = isResponse,
            linkedFrame = linkedFrame,
            text = if (isResponse) responseText else requestText
        )
    }

    private fun pairMessages(messages: List<TransactionMessage>): List<RequestResponseTransaction> {
        val requests = messages.filterNot { it.isResponse }.sortedBy { it.frameNumber }
        val responses = messages.filter { it.isResponse }.sortedBy { it.frameNumber }
        val responsesByFrame = responses.associateBy { it.frameNumber }
        val responsesByRequestFrame = responses.filter { it.linkedFrame != null }.groupBy { it.linkedFrame }
        val usedResponses = mutableSetOf<Long>()
        return requests.map { request ->
            val directlyLinked = request.linkedFrame?.let(responsesByFrame::get)
            val response = if (request.linkedFrame != null) {
                directlyLinked?.takeIf { usedResponses.add(it.frameNumber) }
            } else {
                responsesByRequestFrame[request.frameNumber]
                    ?.firstOrNull { usedResponses.add(it.frameNumber) }
                    ?: responses.firstOrNull {
                        it.key == request.key && it.frameNumber > request.frameNumber && it.frameNumber !in usedResponses
                    }?.also { usedResponses.add(it.frameNumber) }
            }
            RequestResponseTransaction(
                protocol = request.protocol,
                requestFrame = request.frameNumber,
                responseFrame = response?.frameNumber,
                requestTime = request.time,
                responseTime = response?.time,
                client = request.source,
                server = request.destination,
                request = request.text,
                response = response?.text,
                responseTimeMillis = response?.let { ((it.time - request.time) * 1000.0).coerceAtLeast(0.0) }
            )
        }.take(TRANSACTION_LIMIT)
    }

    private fun ProtocolNode.hasAnyField(vararg names: String): Boolean {
        if (filter != null && names.any { filter.equals(it, ignoreCase = true) }) return true
        return children.any { it.hasAnyField(*names) }
    }

    private fun ProtocolNode.firstField(vararg names: String): ProtocolNode? {
        names.forEach { name -> findFirstField(name)?.let { return it } }
        return null
    }

    private fun ProtocolNode.findFirstField(name: String): ProtocolNode? {
        if (filter.equals(name, ignoreCase = true)) return this
        children.forEach { child -> child.findFirstField(name)?.let { return it } }
        return null
    }

    private fun ProtocolNode.firstRawFieldValue(vararg names: String): String? {
        val field = firstField(*names) ?: return null
        return field.filterValue?.takeIf { it.isNotBlank() }
            ?: field.value?.takeIf { it.isNotBlank() }
    }

    private fun ProtocolNode.firstDisplayFieldValue(vararg names: String): String? {
        val field = firstField(*names) ?: return null
        return field.value?.takeIf { it.isNotBlank() }
            ?: field.filterValue?.trim()?.removeSurrounding("\"")?.takeIf { it.isNotBlank() }
    }

    private fun ProtocolNode.firstFrameNumber(fieldName: String): Long? {
        val text = firstRawFieldValue(fieldName) ?: return null
        return FRAME_NUMBER_REGEX.find(text)?.value?.toLongOrNull()
    }

    private fun ProtocolNode.collectDisplayFieldValues(names: Set<String>): List<String> {
        val values = mutableListOf<String>()
        fun visit(node: ProtocolNode) {
            if (node.filter != null && names.any { node.filter.equals(it, ignoreCase = true) }) {
                node.value?.takeIf { it.isNotBlank() }
                    ?.let(values::add)
                    ?: node.filterValue?.trim()?.removeSurrounding("\"")?.takeIf { it.isNotBlank() }?.let(values::add)
            }
            node.children.forEach(::visit)
        }
        visit(this)
        return values
    }

    private fun PacketSummary.timeAsDouble(): Double = time.toDoubleOrNull() ?: 0.0

    private fun PacketSummary.sourceEndpoint(): String = formatEndpoint(source, sourcePort)

    private fun PacketSummary.destinationEndpoint(): String = formatEndpoint(destination, destinationPort)

    private fun PacketSummary.normalizedFlowKey(): String =
        listOf(sourceEndpoint().lowercase(), destinationEndpoint().lowercase()).sorted().joinToString("|")

    private fun formatEndpoint(address: String, port: Int?): String {
        if (port == null) return address
        return if (address.contains(':') && !address.startsWith("[")) "[$address]:$port" else "$address:$port"
    }

    private fun parseCaptureStatistics(json: JSONObject): CaptureStatistics {
        val lengths = json.optJSONObject("packetLengths") ?: JSONObject()
        return CaptureStatistics(
            packetCount = json.optInt("packetCount"),
            byteCount = json.optLong("byteCount"),
            capturedByteCount = json.optLong("capturedByteCount", json.optLong("byteCount")),
            truncatedPacketCount = json.optInt("truncatedPacketCount"),
            startTime = json.optDouble("startTime"),
            endTime = json.optDouble("endTime"),
            protocolHierarchy = json.optJSONArray("protocolHierarchy").mapObjects { item ->
                ProtocolStat(
                    name = item.optString("name", "Unknown"),
                    packetCount = item.optInt("packetCount"),
                    byteCount = item.optLong("byteCount"),
                    packetPercent = item.optDouble("packetPercent"),
                    bytePercent = item.optDouble("bytePercent")
                )
            },
            conversations = json.optJSONArray("conversations").mapObjects { item ->
                ConversationStat(
                    type = item.optString("type"),
                    endpointA = item.optString("endpointA"),
                    endpointB = item.optString("endpointB"),
                    portA = item.optNullableInt("portA"),
                    portB = item.optNullableInt("portB"),
                    packets = item.optInt("packets"),
                    bytes = item.optLong("bytes"),
                    startTime = item.optDouble("startTime"),
                    duration = item.optDouble("duration"),
                    aToBPackets = item.optInt("aToBPackets"),
                    bToAPackets = item.optInt("bToAPackets")
                )
            }.sortedWith(
                compareBy<ConversationStat> { conversationTypeOrder(it.type) }
                    .thenByDescending { it.packets }
            ),
            endpoints = json.optJSONArray("endpoints").mapObjects { item ->
                EndpointStat(
                    type = item.optString("type"),
                    address = item.optString("address"),
                    port = item.optNullableInt("port"),
                    packets = item.optInt("packets"),
                    bytes = item.optLong("bytes"),
                    sentPackets = item.optInt("sentPackets"),
                    receivedPackets = item.optInt("receivedPackets")
                )
            }.sortedWith(
                compareBy<EndpointStat> { endpointTypeOrder(it.type) }
                    .thenByDescending { it.packets }
            ),
            ioGraph = json.optJSONArray("ioGraph").mapObjects { item ->
                IoBucket(
                    startTime = item.optDouble("startTime"),
                    endTime = item.optDouble("endTime"),
                    packets = item.optInt("packets"),
                    bytes = item.optLong("bytes")
                )
            },
            packetLengths = PacketLengthStats(
                min = lengths.optInt("min"),
                max = lengths.optInt("max"),
                average = lengths.optDouble("average"),
                totalBytes = lengths.optLong("totalBytes"),
                buckets = lengths.optJSONArray("buckets").mapObjects { item ->
                    PacketLengthBucket(
                        label = item.optString("label"),
                        packets = item.optInt("packets"),
                        bytes = item.optLong("bytes")
                    )
                }
            ),
            dnsSummaries = json.optJSONArray("dnsSummaries").toProtocolSummaries(),
            dnsSummaryTotal = json.optInt("dnsSummaryTotal"),
            dnsQueries = json.optInt("dnsQueries"),
            dnsResponses = json.optInt("dnsResponses"),
            dnsAverageResponseMs = json.optDouble("dnsAverageResponseMs"),
            dnsTopDomains = json.optIntMap("dnsTopDomains"),
            httpSummaries = json.optJSONArray("httpSummaries").toProtocolSummaries(),
            httpSummaryTotal = json.optInt("httpSummaryTotal"),
            tlsSummaries = json.optJSONArray("tlsSummaries").toProtocolSummaries(),
            tlsSummaryTotal = json.optInt("tlsSummaryTotal"),
            tcpSummaries = json.optJSONArray("tcpSummaries").toProtocolSummaries(),
            tcpSummaryTotal = json.optInt("tcpSummaryTotal"),
            tcpSyn = json.optInt("tcpSyn"),
            tcpSynAck = json.optInt("tcpSynAck"),
            tcpRetransmissions = json.optInt("tcpRetransmissions"),
            tcpDuplicateAcks = json.optInt("tcpDuplicateAcks"),
            tcpResets = json.optInt("tcpResets"),
            tcpZeroWindows = json.optInt("tcpZeroWindows"),
            tcpAverageRttMs = json.optDouble("tcpAverageRttMs"),
            tcpRttSamples = json.optInt("tcpRttSamples"),
            tlsVersions = json.optIntMap("tlsVersions"),
            tlsSni = json.optIntMap("tlsSni"),
            httpStatusCodes = json.optIntMap("httpStatusCodes"),
            httpHosts = json.optIntMap("httpHosts"),
            dnsFailureTotal = json.optInt("dnsFailureTotal"),
            tlsAlertTotal = json.optInt("tlsAlertTotal"),
            httpErrorTotal = json.optInt("httpErrorTotal"),
            dnsFirstFailureFrame = json.optLong("dnsFirstFailureFrame").takeIf { it > 0 },
            tlsFirstAlertFrame = json.optLong("tlsFirstAlertFrame").takeIf { it > 0 },
            httpFirstErrorFrame = json.optLong("httpFirstErrorFrame").takeIf { it > 0 }
        )
    }

    private inline fun <T> JSONArray?.mapObjects(transform: (JSONObject) -> T): List<T> {
        if (this == null) return emptyList()
        return List(length()) { index -> transform(getJSONObject(index)) }
    }

    private fun JSONArray?.toStringList(): List<String> {
        if (this == null) return emptyList()
        return List(length(), ::optString).filter { it.isNotBlank() }.distinct()
    }

    private fun JSONArray?.toProtocolSummaries(): List<ProtocolSummaryItem> = mapObjects { item ->
        ProtocolSummaryItem(
            frameNumber = item.optLong("frameNumber"),
            time = item.optDouble("time"),
            source = item.optString("source"),
            destination = item.optString("destination"),
            protocol = item.optString("protocol"),
            summary = item.optString("summary")
        )
    }

    private fun JSONObject.optNullableInt(name: String): Int? =
        if (isNull(name) || !has(name)) null else optInt(name)

    private fun JSONObject.optNullableLong(name: String): Long? =
        if (isNull(name) || !has(name)) null else optLong(name)

    private fun JSONObject.optNullableString(name: String): String? =
        if (isNull(name) || !has(name)) null else optString(name).takeIf { it.isNotBlank() }

    private fun JSONObject.optNullableBoolean(name: String): Boolean? =
        if (isNull(name) || !has(name)) null else optBoolean(name)

    private fun JSONObject.optStringMap(name: String): Map<String, String> {
        val value = optJSONObject(name) ?: return emptyMap()
        return value.keys().asSequence().associateWith { key -> value.optString(key) }
            .filterValues { it.isNotBlank() }
    }

    private fun JSONObject.optIntMap(name: String): Map<String, Int> {
        val value = optJSONObject(name) ?: return emptyMap()
        return value.keys().asSequence().associateWith { value.optInt(it) }
    }

    private fun JSONArray?.toExpertItems(): List<ExpertInfoItem> {
        if (this == null) return emptyList()
        return buildList {
            for (i in 0 until length()) {
                val item = getJSONObject(i)
                add(
                    ExpertInfoItem(
                        frameNumber = item.optLong("frameNumber"),
                        label = item.optString("label"),
                        filter = item.optString("filter").ifBlank { null },
                        severity = item.optString("severity", "none"),
                        start = item.optInt("start", 0),
                        length = item.optInt("length", 0)
                    )
                )
            }
        }
    }

    private fun ByteArray.selectedRange(range: IntRange?): ByteArray {
        if (range == null || isEmpty()) return this
        val start = range.first.coerceIn(indices)
        val end = range.last.coerceIn(indices)
        if (end < start) return ByteArray(0)
        return copyOfRange(start, end + 1)
    }

    private fun conversationTypeOrder(type: String): Int = when (type) {
        "Ethernet" -> 0
        "IPv4" -> 1
        "IPv6" -> 2
        "TCP" -> 3
        "UDP" -> 4
        else -> 5
    }

    private fun endpointTypeOrder(type: String): Int = when (type) {
        "MAC" -> 0
        "IP" -> 1
        "TCP" -> 2
        "UDP" -> 3
        else -> 4
    }

    private data class TransactionMessage(
        val protocol: String,
        val frameNumber: Long,
        val time: Double,
        val source: String,
        val destination: String,
        val key: String,
        val isResponse: Boolean,
        val linkedFrame: Long?,
        val text: String
    )

    private companion object {
        const val STATISTICS_BATCH_SIZE = 250
        const val TRANSACTION_LIMIT = 500
        const val DNS_ANSWER_LIMIT = 8
        val FRAME_NUMBER_REGEX = Regex("\\d+")
        val HTTP_METHODS = listOf("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ")
        val DNS_ANSWER_FIELDS = setOf(
            "dns.a",
            "dns.aaaa",
            "dns.cname",
            "dns.ptr.domain_name",
            "dns.resp.name",
            "dns.srv.target",
            "dns.txt"
        )
        val ABSOLUTE_TIME_FORMATTER: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
            .withZone(ZoneId.systemDefault())
        val UTC_TIME_FORMATTER: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS'Z'")
            .withZone(ZoneId.of("UTC"))
    }
}
